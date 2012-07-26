#include <assert.h>
#include <errno.h>
#include <malloc.h>
#include <string.h>

#include "common.h"
#include "helper.h"
#include "log.h"
#include "meta_buf.h"

static inline int __can_write_to_head(uint16_t length)
{
	if (length <= sizeof(uint16_t)) {
		return 1;
	} else {
		return 0;
	}
}

static int __have_enough_space(meta_hd_t *head, int16_t data_space)
{
	if (((head->current_head_num + 1) > head->total_head_num) ||
		((head->current_data_size + data_space) > head->total_data_size) || (data_space > MAX_META_SIZE)) {
		return 0;
	} else {
		return 1;
	}
}

static meta_hd_t *__meta_buffer_attr_set(void *buffer, uint16_t meta_max_count, uint32_t buffer_size)
{
	meta_hd_t *meta_hdr;
	uint32_t head_used;

	if_error_return(buffer != NULL, NULL);

	head_used = sizeof(meta_hd_t) + sizeof(meta_info_t) * meta_max_count;
	if_error_return((buffer_size >= head_used ), NULL);
	meta_hdr = (meta_hd_t *)buffer;
    meta_hdr->total_buf_size = buffer_size;
	meta_hdr->total_data_size = buffer_size - head_used;
	meta_hdr->current_data_size = 0;
	meta_hdr->total_head_num = meta_max_count;
	meta_hdr->current_head_num = 0;
	meta_hdr->data_start = buffer + head_used;

	return meta_hdr;
}

meta_hd_t *meta_buffer_sys_create(uint16_t meta_max_count)
{
	meta_hd_t *meta_hdr;
    void *buffer;

    buffer = zmalloc(void *, MAX_META_BUFFER_SIZE);
    if_error_return(buffer != NULL, NULL);
	meta_hdr = __meta_buffer_attr_set(buffer,
                                      meta_max_count,
                                      MAX_META_BUFFER_SIZE);
	return meta_hdr;
}

meta_info_t *meta_buffer_alloc(meta_hd_t *head, uint16_t type, uint16_t length)
{
	meta_info_t *p = NULL;
	if_error_return(head != NULL, NULL);
	if (__have_enough_space(head, length)) {
		p = head->head_info + head->current_head_num;
		p->length = length;
		p->type = type;
		if (!(__can_write_to_head(p->length))) {
			/*大于2字节，置偏移*/
			void *data_buf = head->data_start + head->current_data_size;
			p->u.offset = data_buf - (void *)head;
			head->current_data_size += length;
		}
		head->current_head_num ++;
	}
	return p;
}

int32_t meta_buffer_item_set(meta_hd_t *head, meta_info_t *info, void *data)
{
	void *data_buf;

	if_error_return(head != NULL, -INVALID_PARAM);
	if_error_return(info != NULL, -INVALID_PARAM);

	if (__can_write_to_head(info->length)) {
		data_buf = &info->u.data;
	} else {
		data_buf = (void *)head + info->u.offset;
	}
	memcpy(data_buf, data, info->length);
	return 0;
}

int32_t meta_buffer_item_add(meta_hd_t *head, uint16_t type,
								 void *data, uint16_t length)
{
	meta_info_t *info = meta_buffer_alloc(head, type, length);
	return meta_buffer_item_set(head, info, data);
}

meta_info_t *meta_buffer_item_get(meta_hd_t *head, void *last_pos, uint16_t type)
{
	meta_info_t *info, *p;
	int i;

	if_error_return(head != NULL, NULL);
	if (last_pos == NULL) {
		info = head->head_info;
		i = 0;
	} else {
	    info = last_pos;
		if (!((info >= head->head_info) && ((void *)info < head->data_start))) {
			return NULL;
		} else {
			i = info - head->head_info + 1;
		}

	}
	p = head->head_info;

	while(i <= head->current_head_num) {
		if (p[i].type == type)
			return &p[i];
		i++;
	}

	return NULL;
}

void *meta_buffer_item_get_data(meta_hd_t *head, meta_info_t *info)
{
	if_error_return(head != NULL, NULL);
	if_error_return(info != NULL, NULL);

	if (info->length <= 2) {
		return &info->u.data;
	} else {
		return (void *)head + info->u.offset;
	}
}

int32_t meta_buffer_item_delete(meta_hd_t *head, void *pos, uint32_t size)
{
    /*一般元数据在处理过程中不需要删除，这里暂不实现*/
    return -UNKNOWN_ERROR;
}

int32_t meta_buffer_sys_clear(meta_hd_t *head)
{
    uint32_t size;
    if (head == NULL){
        return -1;
    }
    size = head->total_buf_size - sizeof(meta_hd_t);
    memset(head->head_info, 0, size);
    head->current_head_num  = 0;
    head->current_data_size = 0;
    return 0;
}

void meta_buffer_item_sys_show(meta_hd_t *head, meta_info_t *info)
{
	char *p;

	if (info != NULL) {
		print("%10d %10d\n", info->type, info->length);
		p = (char *)meta_buffer_item_get_data(head, info);
		print("Data:\n");
        list_format_print_buffer(NULL, p, 8, info->length, FORMAT_PRINT_SIMPLE);
		print("\n");
	}
}

void meta_buffer_sys_show(meta_hd_t *head)
{
	int i;

	if (head != NULL) {

		print("%10s %10s\n", "type", "length");

		for (i=0; i<head->current_head_num; i++) {
			meta_info_t *info = head->head_info;
			meta_buffer_item_sys_show(head, &info[i]);
		}
		print("\ntotal space=%d, used_space=%d\n", head->total_data_size, head->current_data_size);
	}
}

void meta_buffer_sys_destroy(meta_hd_t *head)
{
    if (head != NULL) {
        free(head);
    }
}
