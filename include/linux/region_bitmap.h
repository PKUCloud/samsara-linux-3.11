#ifndef __REGION_BITMAP_H
#define __REGION_BITMAP_H
#include <linux/rr_profile.h>
#include <linux/bitmap.h>

#define RE_BITMAP_SIZE	TM_BITMAP_SIZE
#define RE_BITMAP_MAX	0xffffffffffffffffULL
#define RE_BITMAP_MIN	0x0ULL

/* Bitmap with valid region indicators */
struct region_bitmap {
	DECLARE_BITMAP(bitmap, RE_BITMAP_SIZE);
	unsigned long low;
	unsigned long  high;
};

static inline void re_bitmap_init(struct region_bitmap *re_bitmap)
{
	bitmap_clear(re_bitmap->bitmap, 0, RE_BITMAP_SIZE);
	re_bitmap->low = RE_BITMAP_MAX;
	re_bitmap->high = RE_BITMAP_MIN;
}

static inline void re_bitmap_clear(struct region_bitmap *re_bitmap)
{
	unsigned long low, high;

	low = re_bitmap->low;
	high = re_bitmap->high;
	if (likely(low <= high)) {
		/* Just clear bitmap[low, high] */
		bitmap_clear(re_bitmap->bitmap, low, high - low + 1);
	} else {
		bitmap_clear(re_bitmap->bitmap, 0, RE_BITMAP_SIZE);
	}
	re_bitmap->low = RE_BITMAP_MAX;
	re_bitmap->high = RE_BITMAP_MIN;
}

static inline void re_set_bit(unsigned long nr, struct region_bitmap *re_bitmap)
{
	set_bit(nr, re_bitmap->bitmap);
	if (nr < re_bitmap->low)
		re_bitmap->low = nr;
	if (nr > re_bitmap->high)
		re_bitmap->high = nr;
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
	unsigned long low, high;
	int offset;

	low = src->low;
	high = src->high;
	offset = BIT_WORD(low);
	bitmap_or(dst->bitmap + offset, src->bitmap + offset,
		  dst->bitmap + offset, high - low + BITS_PER_LONG);
	dst->low = min(low, dst->low);
	dst->high = max(high, dst->high);
}

static inline int re_bitmap_intersects(const struct region_bitmap *bitmap1,
				       const struct region_bitmap *bitmap2)
{
	const unsigned long *bt1 = bitmap1->bitmap;
	const unsigned long *bt2 = bitmap2->bitmap;
	unsigned long low = max(bitmap1->low, bitmap2->low);
	unsigned long high = min(bitmap1->high, bitmap2->high);
	int first = BIT_WORD(low);
	int last = BITS_TO_LONGS(high);
	int i;

	for (i = first; i <= last; ++i) {
		if (bt1[i] & bt2[i])
			return 1;
	}
	return 0;
}

#endif
