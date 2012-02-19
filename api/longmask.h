#ifndef __LONGMASK_H__
#define __LONGMASK_H__

#include "common.h"

typedef struct longmask {
	uint32_t bit_num; /*最多的bit数*/
	uint8_t data[0];
} longmask_t;

#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "longmask.h"
#include "helper.h"

static inline longmask_t* longmask_create(uint32_t bit_num)
{
	uint32_t bytes = (bit_num + 7) / 8;
	longmask_t *mask;

	if (bytes == 0) {
		return NULL;
	}
	mask= zmalloc(longmask_t *, sizeof(longmask_t) + bytes);
	if (mask != NULL) {
		mask->bit_num = bit_num;
	}

	return mask;
}

static inline void longmask_copy(longmask_t *dst, longmask_t *src)
{
	uint32_t bytes;

	assert(dst->bit_num == src->bit_num);
	bytes = (src->bit_num + 7) / 8;
	memcpy(dst, src, sizeof(longmask_t) + bytes);
}

static inline int32_t longmask_bit1_find(longmask_t *mask, uint32_t start_bit)
{
	uint32_t i;
	uint32_t bytes, offset;
	uint8_t *data;

	if(start_bit >= mask->bit_num) {
		return -1;
	}

	data = mask->data;
	bytes = start_bit/8;
	offset = start_bit % 8;
	data += bytes;

	for (i=start_bit; i<mask->bit_num; i++) {
		if ((*data) & (1<<offset)) {
			return i;
		} else {
			offset++;
			if (offset == 8) {
				offset = 0;
				data++;
			}
		}
	}
	return -1;/*not found*/
}

static inline void longmask_bit_set(longmask_t *mask, uint32_t bit)
{
	uint32_t bytes, offset;
	uint8_t *data;

	assert(mask);
	assert(bit < mask->bit_num);
	data = mask->data;

	bytes =  bit/8;
	offset = bit % 8;

	data += bytes;
	*data |= 1<<offset;
}

static inline int32_t longmask_bit_is_set(longmask_t *mask, uint32_t bit)
{
	uint32_t bytes, offset;
	uint8_t *data;

	assert(mask);
	assert(bit < mask->bit_num);
	data = mask->data;

	bytes =  bit/8;
	offset = bit % 8;

	data += bytes;
    return (*data & (1<<offset)) ? 1: 0;
}

static inline void longmask_bit_clr(longmask_t *mask, uint32_t bit)
{
	uint32_t bytes, offset;
	uint8_t *data;

	assert(mask);
	assert(bit < mask->bit_num);
	data = mask->data;

	bytes =  bit/8;
	offset = bit % 8;

	data += bytes;
	*data &= ~(1<<offset);
}

static inline void longmask_op_and(longmask_t *dst_mask, longmask_t *src_mask)
{
	uint32_t bit_num;
	uint32_t bytes;
	uint32_t i;

	assert(dst_mask->bit_num == src_mask->bit_num);
	bit_num = dst_mask->bit_num;
	bytes = (bit_num + 7) / 8;

	for (i=0; i<bytes; i++) {
		dst_mask->data[i] &= src_mask->data[i];
	}
}

static inline void longmask_all_clr(longmask_t *mask)
{
	uint32_t bytes = (mask->bit_num + 7) / 8;

	memset(mask->data, 0, bytes);
}

static inline void longmask_debug_print(longmask_t *mask)
{
	uint8_t *data = mask->data;
	uint32_t i,j;

	for (i=0, j=0; i<mask->bit_num; i++) {
		if (*data & (1<<j)) {
			print("1");
		} else {
			print("0");
		}
		j++;
		if (j== 8) {
			j=0;
			data++;
		}
	}
	printf("\n");
}

static inline void longmask_destroy(longmask_t *mask)
{
	if (mask != NULL) {
		free(mask);
	}
}

#endif
