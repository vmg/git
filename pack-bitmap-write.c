#include <stdlib.h>

#include "cache.h"
#include "commit.h"
#include "tag.h"
#include "diff.h"
#include "revision.h"
#include "list-objects.h"
#include "progress.h"
#include "pack-revindex.h"
#include "pack.h"
#include "pack-bitmap.h"
#include "builtin/pack-objects.h"

struct bitmapped_commit {
	struct commit *commit;
	struct ewah_bitmap *bitmap;
	struct ewah_bitmap *write_as;
	int flags;
	int xor_offset;
	uint32_t write_pos;
};

struct bitmap_writer {
	struct ewah_bitmap *commits;
	struct ewah_bitmap *trees;
	struct ewah_bitmap *blobs;
	struct ewah_bitmap *tags;

	khash_sha1 *bitmaps;
	khash_sha1 *packed_objects;

	struct bitmapped_commit *selected;
	unsigned int selected_nr, selected_alloc;

	struct object_entry **index;
	uint32_t index_nr;

	int fd;
	uint32_t written;

	struct progress *progress;
	int show_progress;
};

static struct bitmap_writer writer;

void bitmap_writer_show_progress(int show)
{
	writer.show_progress = show;
}

/**
 * Build the initial type index for the packfile
 */
void bitmap_writer_build_type_index(
	 struct pack_idx_entry **index, uint32_t index_nr)
{
	uint32_t i = 0;

	if (writer.show_progress)
		writer.progress = start_progress("Building bitmap type index", index_nr);

	writer.commits = ewah_new();
	writer.trees = ewah_new();
	writer.blobs = ewah_new();
	writer.tags = ewah_new();

	writer.index = (struct object_entry **)index;
	writer.index_nr = index_nr;

	while (i < index_nr) {
		struct object_entry *entry = (struct object_entry *)index[i];
		entry->index_pos = i;

		switch (entry->real_type) {
		case OBJ_COMMIT:
			ewah_set(writer.commits, i);
			break;

		case OBJ_TREE:
			ewah_set(writer.trees, i);
			break;

		case OBJ_BLOB:
			ewah_set(writer.blobs, i);
			break;

		case OBJ_TAG:
			ewah_set(writer.tags, i);
			break;

		default:
			die("Missing type information for %s (%d/%d)",
					sha1_to_hex(entry->idx.sha1), entry->real_type, entry->type);
		}

		i++;
		display_progress(writer.progress, i);
	}

	stop_progress(&writer.progress);
}

/**
 * Compute the actual bitmaps
 */
static struct object **seen_objects;
static unsigned int seen_objects_nr, seen_objects_alloc;

static inline void push_bitmapped_commit(struct commit *commit)
{
	if (writer.selected_nr >= writer.selected_alloc) {
		writer.selected_alloc = (writer.selected_alloc + 32) * 2;
		writer.selected = xrealloc(writer.selected,
			writer.selected_alloc * sizeof(struct bitmapped_commit));
	}

	writer.selected[writer.selected_nr].commit = commit;
	writer.selected[writer.selected_nr].bitmap = NULL;
	writer.selected[writer.selected_nr].flags = 0;

	writer.selected_nr++;
}

static inline void mark_as_seen(struct object *object)
{
	if (seen_objects_nr >= seen_objects_alloc) {
		seen_objects_alloc = (seen_objects_alloc + 32) * 2;
		seen_objects = xrealloc(seen_objects,
			seen_objects_alloc * sizeof(struct object*));
	}

	seen_objects[seen_objects_nr++] = object;
}

static inline void reset_all_seen(void)
{
	unsigned int i;
	for (i = 0; i < seen_objects_nr; ++i) {
		seen_objects[i]->flags &= ~(SEEN | ADDED | SHOWN);
	}
	seen_objects_nr = 0;
}

static uint32_t find_object_pos(const unsigned char *sha1)
{
	khiter_t pos = kh_get_sha1(writer.packed_objects, sha1);

	if (pos < kh_end(writer.packed_objects)) {
		struct object_entry *entry = kh_value(writer.packed_objects, pos);
		return entry->index_pos;
	}

	die("Failed to write bitmap index. Packfile doesn't have full closure "
		"(object %s is missing)", sha1_to_hex(sha1));
}

static void show_object(struct object *object,
	const struct name_path *path, const char *last, void *data)
{
	struct bitmap *base = data;
	bitmap_set(base, find_object_pos(object->sha1));
	mark_as_seen(object);
}

static void show_commit(struct commit *commit, void *data)
{
	mark_as_seen((struct object *)commit);
}

static int
add_to_include_set(struct bitmap *base, struct commit *commit)
{
	khiter_t hash_pos;
	uint32_t bitmap_pos = find_object_pos(commit->object.sha1);

	if (bitmap_get(base, bitmap_pos))
		return 0;

	hash_pos = kh_get_sha1(writer.bitmaps, commit->object.sha1);
	if (hash_pos < kh_end(writer.bitmaps)) {
		struct bitmapped_commit *bc = kh_value(writer.bitmaps, hash_pos);
		bitmap_or_ewah(base, bc->bitmap);
		return 0;
	}

	bitmap_set(base, bitmap_pos);
	return 1;
}

static int
should_include(struct commit *commit, void *_data)
{
	struct bitmap *base = _data;

	if (!add_to_include_set(base, commit)) {
		struct commit_list *parent = commit->parents;

		mark_as_seen((struct object *)commit);

		while (parent) {
			parent->item->object.flags |= SEEN;
			mark_as_seen((struct object *)parent->item);
			parent = parent->next;
		}

		return 0;
	}

	return 1;
}

static void
compute_xor_offsets(void)
{
	static const int MAX_XOR_OFFSET_SEARCH = 10;

	int i, next = 0;

	while (next < writer.selected_nr) {
		struct bitmapped_commit *stored = &writer.selected[next];

		int best_offset = 0;
		struct ewah_bitmap *best_bitmap = stored->bitmap;
		struct ewah_bitmap *test_xor;

		for (i = 1; i <= MAX_XOR_OFFSET_SEARCH; ++i) {
			int curr = next - i;

			if (curr < 0)
				break;

			test_xor = ewah_pool_new();
			ewah_xor(writer.selected[curr].bitmap, stored->bitmap, test_xor);

			if (test_xor->buffer_size < best_bitmap->buffer_size) {
				if (best_bitmap != stored->bitmap)
					ewah_pool_free(best_bitmap);

				best_bitmap = test_xor;
				best_offset = i;
			} else {
				ewah_pool_free(test_xor);
			}
		}

		stored->xor_offset = best_offset;
		stored->write_as = best_bitmap;

		next++;
	}
}

void
bitmap_writer_build(khash_sha1 *packed_objects)
{
	int i;
	struct bitmap *base = bitmap_new();
	struct rev_info revs;

	writer.bitmaps = kh_init_sha1();
	writer.packed_objects = packed_objects;

	if (writer.show_progress)
		writer.progress = start_progress("Building bitmaps", writer.selected_nr);

	init_revisions(&revs, NULL);
	revs.tag_objects = 1;
	revs.tree_objects = 1;
	revs.blob_objects = 1;
	revs.no_walk = 0;

	revs.include_check = should_include;
	reset_revision_walk();

	for (i = writer.selected_nr - 1; i >= 0; --i) {
		struct bitmapped_commit *stored;
		struct object *object;

		khiter_t hash_pos;
		int hash_ret;

		stored = &writer.selected[i];
		object = (struct object *)stored->commit;

		if (i < writer.selected_nr - 1) {
			if (!in_merge_bases(writer.selected[i + 1].commit, stored->commit)) {
				bitmap_reset(base);
				reset_all_seen();
			}
		}

		add_pending_object(&revs, object, "");
		revs.include_check_data = base;

		if (prepare_revision_walk(&revs))
			die("revision walk setup failed");

		traverse_commit_list(&revs, show_commit, show_object, base);

		revs.pending.nr = 0;
		revs.pending.alloc = 0;
		revs.pending.objects = NULL;

		stored->bitmap = bitmap_to_ewah(base);
		stored->flags = object->flags;

		hash_pos = kh_put_sha1(writer.bitmaps, object->sha1, &hash_ret);
		if (hash_ret == 0)
			die("Duplicate entry when writing index: %s",
				sha1_to_hex(object->sha1));

		kh_value(writer.bitmaps, hash_pos) = stored;

		display_progress(writer.progress, writer.selected_nr - i);
	}

	bitmap_free(base);
	stop_progress(&writer.progress);

	compute_xor_offsets();
}

/**
 * Select the commits that will be bitmapped
 */
static inline unsigned int next_commit_index(unsigned int idx)
{
	static const unsigned int MIN_COMMITS = 100;
	static const unsigned int MAX_COMMITS = 5000;

	static const unsigned int MUST_REGION = 100;
	static const unsigned int MIN_REGION = 20000;

	unsigned int offset, next;

	if (idx <= MUST_REGION)
		return 0;

	if (idx <= MIN_REGION) {
		offset = idx - MUST_REGION;
		return (offset < MIN_COMMITS) ? offset : MIN_COMMITS;
	}

	offset = idx - MIN_REGION;
	next = (offset < MAX_COMMITS) ? offset : MAX_COMMITS;

	return (next > MIN_COMMITS) ? next : MIN_COMMITS;
}

void bitmap_writer_select_commits(
		struct commit **indexed_commits,
		unsigned int indexed_commits_nr,
		int max_bitmaps)
{
	unsigned int i = 0, next;

	if (writer.show_progress)
		writer.progress = start_progress("Selecting bitmap commits", 0);

	if (indexed_commits_nr < 100) {
		for (i = 0; i < indexed_commits_nr; ++i) {
			push_bitmapped_commit(indexed_commits[i]);
		}
		return;
	}

	for (;;) {
		next = next_commit_index(i);

		if (i + next >= indexed_commits_nr)
			break;

		if (max_bitmaps > 0 && writer.selected_nr >= max_bitmaps) {
			writer.selected_nr = max_bitmaps;
			break;
		}

		if (next == 0) {
			push_bitmapped_commit(indexed_commits[i]);
		} else {
			unsigned int j;
			struct commit *chosen = indexed_commits[i + next];

			for (j = 0; j <= next; ++j) {
				struct commit *cm = indexed_commits[i + j];
				if (cm->parents && cm->parents->next)
					chosen = cm;
			}

			push_bitmapped_commit(chosen);
		}

		i += next + 1;
		display_progress(writer.progress, i);
	}

	stop_progress(&writer.progress);
}

/**
 * Write the bitmap index to disk
 */
static void write_hash_table(
	 struct object_entry **index, uint32_t index_nr)
{
	uint32_t i, j = 0;
	uint32_t buffer[1024];

	for (i = 0; i < index_nr; ++i) {
		struct object_entry *entry = index[i];

		buffer[j++] = htonl(entry->hash);
		if (j == 1024) {
			write_or_die(writer.fd, buffer, sizeof(buffer));
			j = 0;
		}
	}

	if (j > 0) {
		write_or_die(writer.fd, buffer, j * sizeof(uint32_t));
	}

	writer.written += (index_nr * sizeof(uint32_t));
}

static void dump_bitmap(struct ewah_bitmap *bitmap)
{
	int written = ewah_serialize(bitmap, writer.fd);

	if (written < 0)
		die("Failed to write bitmap index");

	writer.written += written;
}

static void
write_selected_commits_v2(void)
{
	int i;

	for (i = 0; i < writer.selected_nr; ++i) {
		struct bitmapped_commit *stored = &writer.selected[i];
		stored->write_pos = writer.written;
		dump_bitmap(stored->write_as);
	}

	for (i = 0; i < writer.selected_nr; ++i) {
		struct bitmapped_commit *stored = &writer.selected[i];
		struct bitmap_disk_entry_v2 on_disk;

		memcpy(on_disk.sha1, stored->commit->object.sha1, 20);
		on_disk.bitmap_pos = htonl(stored->write_pos);
		on_disk.xor_offset = stored->xor_offset;
		on_disk.flags = stored->flags;

		write_or_die(writer.fd, &on_disk, sizeof(on_disk));
		writer.written += sizeof(on_disk);
	}
}

void bitmap_writer_finish(
	 const char *filename, unsigned char sha1[], uint16_t flags)
{
	static char tmp_file[PATH_MAX];
	static uint16_t default_version = 2;

	struct bitmap_disk_header header;

	flags |= BITMAP_OPT_FULL_DAG;

	writer.fd = odb_mkstemp(tmp_file, sizeof(tmp_file), "pack/tmp_bitmap_XXXXXX");

	if (writer.fd < 0)
		die_errno("unable to create '%s'", tmp_file);

	memcpy(header.magic, BITMAP_IDX_SIGNATURE, sizeof(BITMAP_IDX_SIGNATURE));
	header.version = htons(default_version);
	header.options = htons(flags);
	header.entry_count = htonl(writer.selected_nr);
	memcpy(header.checksum, sha1, 20);

	write_or_die(writer.fd, &header, sizeof(header));
	writer.written += sizeof(header);

	if (flags & BITMAP_OPT_HASH_CACHE)
		write_hash_table(writer.index, writer.index_nr);

	dump_bitmap(writer.commits);
	dump_bitmap(writer.trees);
	dump_bitmap(writer.blobs);
	dump_bitmap(writer.tags);
	write_selected_commits_v2();

	close(writer.fd);

	if (adjust_shared_perm(tmp_file))
		die_errno("unable to make temporary bitmap file readable");

	if (rename(tmp_file, filename))
		die_errno("unable to rename temporary bitmap file to '%s'", filename);
}
