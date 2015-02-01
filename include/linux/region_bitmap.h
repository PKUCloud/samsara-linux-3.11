#ifndef __REGION_BITMAP_H
#define __REGION_BITMAP_H
#include <linux/rr_profile.h>
#include <linux/bitmap.h>
#include <linux/slab.h>

#define RE_BITMAP_SIZE	TM_BITMAP_SIZE
#define RE_BITMAP_MAX	0xffffffffffffffffULL
#define RE_BITMAP_MIN	0x0ULL

struct bits_list {
	int nbits;	/* Number of valid bits in the list */
	int capacity;	/* Current capacity of array bits */
	unsigned long *bits;
};

static inline void bits_list_init(struct bits_list *blist)
{
	blist->nbits = 0;
	blist->capacity = 1024;
	blist->bits = kmalloc(blist->capacity * sizeof(unsigned long), GFP_ATOMIC);
	if (unlikely(!blist->bits)) {
		printk(KERN_ERR "error: %s fail to kmalloc\n", __func__);
	}
}

static inline void bits_list_destroy(struct bits_list *blist)
{
	blist->nbits = 0;
	blist->capacity = 0;
	if (blist->bits) {
		kfree(blist->bits);
	}
}

static inline void bits_list_clear(struct bits_list *blist)
{
	blist->nbits = 0;
}

static inline void bits_list_insert(struct bits_list *blist, unsigned long ele)
{
	unsigned long *temp;
	int new_cap, old_cap;
	int i;

	if (likely(blist->nbits < blist->capacity)) {
		blist->bits[blist->nbits++] = ele;
	} else {
		/* Realloc more space */
		old_cap = blist->capacity;
		new_cap = blist->capacity * 2;
		temp = kmalloc(new_cap * sizeof(unsigned long), GFP_ATOMIC);
		if (unlikely(!temp)) {
			printk(KERN_ERR "error: %s fail to kmalloc\n",
			       __func__);
			return;
		}
		blist->capacity = new_cap;
		for (i = 0; i < old_cap; ++i) {
			temp[i] = blist->bits[i];
		}
		kfree(blist->bits);
		blist->bits = temp;

		blist->bits[blist->nbits++] = ele;
		printk(KERN_INFO "%s need to reallocate the list to size %d\n",
		       __func__, new_cap);
	}
}

/* Bitmap with valid region indicators */
struct region_bitmap {
	DECLARE_BITMAP(bitmap, RE_BITMAP_SIZE);
	unsigned long low;
	unsigned long  high;
	bool bits_list_valid;	/* Whether region_bitmap->bits is valid */
	struct bits_list blist;
};

static inline void re_bitmap_init(struct region_bitmap *re_bitmap,
				  bool bits_list_valid)
{
	bitmap_clear(re_bitmap->bitmap, 0, RE_BITMAP_SIZE);
	re_bitmap->low = RE_BITMAP_MAX;
	re_bitmap->high = RE_BITMAP_MIN;
	re_bitmap->bits_list_valid = bits_list_valid;

	bits_list_init(&re_bitmap->blist);
}

static inline void re_bitmap_clear(struct region_bitmap *re_bitmap)
{
	unsigned long low, high;
	int i, size;
	struct bits_list *blist = &re_bitmap->blist;
	unsigned long *bitmap = re_bitmap->bitmap;

	if (re_bitmap->bits_list_valid) {
		/* Clear the bitmap through the list */
		size = blist->nbits;
		for (i = 0; i < size; ++i) {
			clear_bit(blist->bits[i], bitmap);
		}
		goto out;
	}
	low = re_bitmap->low;
	high = re_bitmap->high;
	if (likely(low <= high)) {
		/* Just clear bitmap[low, high] */
		bitmap_clear(re_bitmap->bitmap, low, high - low + 1);
	} else {
		bitmap_clear(re_bitmap->bitmap, 0, RE_BITMAP_SIZE);
	}
out:
	re_bitmap->low = RE_BITMAP_MAX;
	re_bitmap->high = RE_BITMAP_MIN;

	bits_list_clear(&re_bitmap->blist);
}

static inline void re_bitmap_destroy(struct region_bitmap *re_bitmap)
{
	bits_list_destroy(&re_bitmap->blist);
}

static inline void re_set_bit(unsigned long nr, struct region_bitmap *re_bitmap)
{
	set_bit(nr, re_bitmap->bitmap);
	if (nr < re_bitmap->low)
		re_bitmap->low = nr;
	if (nr > re_bitmap->high)
		re_bitmap->high = nr;

	if (re_bitmap->bits_list_valid) {
		bits_list_insert(&re_bitmap->blist, nr);
	}
}

static inline int re_test_bit(unsigned long nr, struct region_bitmap *re_bitmap)
{
	if (nr < re_bitmap->low || nr > re_bitmap->high)
		return 0;
	return test_bit(nr, re_bitmap->bitmap);
}

/* dst = dst | src */
static inline void re_bitmap_or(struct region_bitmap *dst,
				const struct region_bitmap *src)
{
	int i, size;
	const struct bits_list *blist = &src->blist;
	unsigned long *bitmap = dst->bitmap;

	/* Assumptions based on our system */
	if (unlikely(!src->bits_list_valid || dst->bits_list_valid)) {
		printk(KERN_ERR "error: %s region_bitmap error\n", __func__);
	}
	size = blist->nbits;
	for (i = 0; i < size; ++i) {
		set_bit(blist->bits[i], bitmap);
	}
	dst->low = min(src->low, dst->low);
	dst->high = max(src->high, dst->high);
}

static inline int re_bitmap_intersects(struct region_bitmap *bitmap1,
				       struct region_bitmap *bitmap2)
{
	int i, size;
	struct bits_list *blist = &bitmap2->blist;

	/* Assumptions based on our system */
	if (unlikely(!bitmap2->bits_list_valid || bitmap1->bits_list_valid)) {
		printk(KERN_ERR "error: %s region_bitmap error\n", __func__);
	}
	size = blist->nbits;
	for (i = 0; i < size; ++i) {
		if (re_test_bit(blist->bits[i], bitmap1))
			return 1;
	}
	return 0;
}

#endif
