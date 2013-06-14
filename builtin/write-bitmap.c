#include <stdlib.h>

#include "cache.h"
#include "commit.h"
#include "tag.h"
#include "diff.h"
#include "revision.h"
#include "progress.h"
#include "list-objects.h"
#include "pack.h"
#include "refs.h"
#include "pack-bitmap.h"

#include "builtin/pack-objects.h"

static int progress = 1;
static struct progress *progress_state;
static int write_hash_cache;

static struct object_entry **objects;
static uint32_t nr_objects;

static struct commit **walked_commits;
static uint32_t nr_commits;

static khash_sha1 *packed_objects;

static struct object_entry *
allocate_entry(const unsigned char *sha1)
{
	struct object_entry *entry;
	khiter_t pos;
	int hash_ret;

	entry = calloc(1, sizeof(struct object_entry));
	hashcpy(entry->idx.sha1, sha1);

	pos = kh_put_sha1(packed_objects, entry->idx.sha1, &hash_ret);
	if (hash_ret == 0) {
		die("BUG: duplicate entry in packfile");
	}

	kh_value(packed_objects, pos) = entry;
	objects[nr_objects++] = entry;

	return entry;
}

static void
load_pack_index(struct packed_git *pack)
{
	uint32_t i, commits_found = 0;
	khint_t new_hash_size, nr_alloc;

	if (open_pack_index(pack))
		die("Failed to load packfile");

	new_hash_size = (pack->num_objects * (1.0 / __ac_HASH_UPPER)) + 0.5;
	kh_resize_sha1(packed_objects, new_hash_size);

	nr_alloc = (pack->num_objects + 63) & ~63;
	objects = xmalloc(nr_alloc * sizeof(struct object_entry *));

	if (progress)
		progress_state = start_progress("Loading existing index", pack->num_objects);

	for (i = 0; i < pack->num_objects; ++i) {
		struct object_entry *entry;
		const unsigned char *sha1;

		sha1 = nth_packed_object_sha1(pack, i);
		entry = allocate_entry(sha1);

		entry->in_pack = pack;
		entry->type = entry->real_type = nth_packed_object_info(pack, i, NULL);
		entry->index_pos = i;

		display_progress(progress_state, i + 1);
	}

	stop_progress(&progress_state);
	if (progress)
		progress_state = start_progress("Finding pack closure", 0);

	for (i = 0; i < nr_objects; ++i) {
		struct commit *commit;
		struct commit_list *parent;

		if (objects[i]->type != OBJ_COMMIT)
			continue;

		commit = lookup_commit(objects[i]->idx.sha1);
		if (parse_commit(commit)) {
			die("Bad commit: %s\n", sha1_to_hex(objects[i]->idx.sha1));
		}

		parent = commit->parents;

		while (parent) {
			khiter_t pos = kh_get_sha1(packed_objects, parent->item->object.sha1);

			if (pos < kh_end(packed_objects)) {
				struct object_entry *entry = kh_value(packed_objects, pos);
				entry->refered = 1;
			} else {
				die("Failed to write bitmaps for packfile: No closure");
			}

			parent = parent->next;
		}

		display_progress(progress_state, ++commits_found);
	}

	stop_progress(&progress_state);
}

static void show_object(struct object *object,
	const struct name_path *path, const char *last, void *data)
{
	char *name = path_name(path, last);
	khiter_t pos = kh_get_sha1(packed_objects, object->sha1);

	if (pos < kh_end(packed_objects)) {
		struct object_entry *entry = kh_value(packed_objects, pos);
		entry->hash = pack_name_hash(name);
	}

	free(name);
}

static void show_commit(struct commit *commit, void *data)
{
	walked_commits[nr_commits++] = commit;
	display_progress(progress_state, nr_commits);
}

static void
find_all_objects(struct packed_git *pack)
{
	struct rev_info revs;
	uint32_t i, found_commits = 0;

	init_revisions(&revs, NULL);
	if (write_hash_cache) {
		revs.tag_objects = 1;
		revs.tree_objects = 1;
		revs.blob_objects = 1;
	}
	revs.no_walk = 0;

	for (i = 0; i < nr_objects; ++i) {
		if (objects[i]->type == OBJ_COMMIT) {
			if (!objects[i]->refered) {
				struct object *object = parse_object(objects[i]->idx.sha1);
				add_pending_object(&revs, object, "");
			}

			found_commits++;
		}
	}

	if (progress)
		progress_state = start_progress("Computing walk order", found_commits);

	walked_commits = xmalloc(found_commits * sizeof(struct commit *));

	if (prepare_revision_walk(&revs))
		die("revision walk setup failed");

	traverse_commit_list(&revs, show_commit, show_object, NULL);
	stop_progress(&progress_state);

	if (found_commits != nr_commits)
		die("Missing commits in the walk? Got %d, expected %d", i, nr_commits);
}

static const char *write_bitmaps_usage[] = {
	N_("git write-bitmap --hash-cache [options...] [pack-sha1]"),
	NULL
};

int cmd_write_bitmap(int argc, const char **argv, const char *prefix)
{
	int max_bitmaps = 0;

	struct option write_bitmaps_options[] = {
		OPT_SET_INT('q', "quiet", &progress,
			    N_("do not show progress meter"), 0),
		OPT_SET_INT(0, "progress", &progress,
			    N_("show progress meter"), 1),
		OPT_BOOL(0, "hash-cache", &write_hash_cache,
			 N_("Write a cache of hashes for delta resolution")),
		OPT_INTEGER(0, "max", &max_bitmaps,
			    N_("max number of bitmaps to generate")),
		OPT_END(),
	};

	struct packed_git *p;
	struct packed_git *pack_to_index = NULL;
	char *bitmap_filename;
	uint16_t write_flags;

	progress = isatty(2);
	argc = parse_options(argc, argv, prefix,
			write_bitmaps_options, write_bitmaps_usage, 0);

	packed_objects = kh_init_sha1();
	prepare_packed_git();

	if (argc) {
		unsigned char pack_sha[20];

		if (get_sha1_hex(argv[0], pack_sha))
			die("Invalid SHA1 for packfile");

		for (p = packed_git; p; p = p->next) {
			if (hashcmp(p->sha1, pack_sha) == 0) {
				pack_to_index = p;
				break;
			}
		}
	} else {
		pack_to_index = packed_git;

		for (p = packed_git; p; p = p->next) {
			if (p->pack_size > pack_to_index->pack_size)
				pack_to_index = p;
		}
	}

	if (!pack_to_index)
		die("No packs found for indexing");

	if (progress)
		fprintf(stderr, "Indexing 'pack-%s.pack'\n",
			sha1_to_hex(pack_to_index->sha1));

	load_pack_index(pack_to_index);
	find_all_objects(pack_to_index);

	bitmap_filename = pack_bitmap_filename(pack_to_index);
	write_flags = 0;

	if (write_hash_cache)
		write_flags |= BITMAP_OPT_HASH_CACHE;

	bitmap_writer_show_progress(progress);
	bitmap_writer_build_type_index((struct pack_idx_entry **)objects, nr_objects);
	bitmap_writer_select_commits(walked_commits, nr_commits, max_bitmaps);
	bitmap_writer_build(packed_objects);
	bitmap_writer_finish(bitmap_filename, pack_to_index->sha1, write_flags);

	free(bitmap_filename);
	return 0;
}
