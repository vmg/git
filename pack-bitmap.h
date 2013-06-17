#ifndef PACK_BITMAP_H
#define PACK_BITMAP_H

#define ewah_malloc xmalloc
#define ewah_calloc xcalloc
#define ewah_realloc xrealloc
#include "ewah/ewok.h"
#include "khash.h"

struct bitmap_disk_entry {
	uint32_t object_pos;
	uint8_t xor_offset;
	uint8_t flags;
};

struct bitmap_disk_entry_v2 {
	unsigned char sha1[20];
	uint32_t bitmap_pos;
	uint8_t xor_offset;
	uint8_t flags;
	uint8_t __pad[2];
};

struct bitmap_disk_header {
	char magic[4];
	uint16_t version;
	uint16_t options;
	uint32_t entry_count;
	unsigned char checksum[20];
};

static const char BITMAP_IDX_SIGNATURE[] = {'B', 'I', 'T', 'M'};;

#define NEEDS_BITMAP (1u<<22)

enum pack_bitmap_opts {
	BITMAP_OPT_FULL_DAG = 1,
	BITMAP_OPT_HASH_CACHE = 8
};

typedef int (*show_reachable_fn)(
	const unsigned char *sha1,
	enum object_type type,
	uint32_t hash, int exclude,
	struct packed_git *found_pack,
	off_t found_offset);

void count_bitmap_commit_list(
	uint32_t *commits, uint32_t *trees, uint32_t *blobs, uint32_t *tags);
void traverse_bitmap_commit_list(show_reachable_fn show_reachable);
int prepare_bitmap_walk(struct rev_info *revs, uint32_t *result_size);
void test_bitmap_walk(struct rev_info *revs);
char *pack_bitmap_filename(struct packed_git *p);

void bitmap_writer_show_progress(int show);
void bitmap_writer_build_type_index(struct pack_idx_entry **index, uint32_t index_nr);
void bitmap_writer_select_commits(struct commit **indexed_commits,
		unsigned int indexed_commits_nr, int max_bitmaps);
void bitmap_writer_build(khash_sha1 *packed_objects);
void bitmap_writer_finish(const char *filename, unsigned char sha1[], uint16_t flags);

#endif
