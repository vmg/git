#ifndef BUILTIN_PACK_OBJECTS_H
#define BUILTIN_PACK_OBJECTS_H

struct object_entry {
	struct pack_idx_entry idx;
	unsigned long size;	/* uncompressed size */
	struct packed_git *in_pack; 	/* already in pack */
	off_t in_pack_offset;
	struct object_entry *delta;	/* delta base object */
	struct object_entry *delta_child; /* deltified objects who bases me */
	struct object_entry *delta_sibling; /* other deltified objects who
					     * uses the same base as me
					     */
	void *delta_data;	/* cached delta (uncompressed) */
	unsigned long delta_size;	/* delta data size (uncompressed) */
	unsigned long z_delta_size;	/* delta data size (compressed) */
	unsigned int hash;	/* name hint hash */

	enum object_type type;
	enum object_type in_pack_type;
	enum object_type real_type;

	unsigned int index_pos;

	unsigned char in_pack_header_size;
	unsigned char preferred_base;
	unsigned char no_try_delta;
	unsigned char tagged;
	unsigned char filled;
	unsigned char refered;
};

#endif
