#ifndef __PLUGIN_H__
#define __PLUGIN_H__

#include "parser.h"
#include "list.h"
#include "code.h"
#include "longmask.h"
#include "helper.h"

typedef struct protobuf_node {
	list_head_t list;
	uint32_t engine_id;
	longmask_t *match_mask;
	uint32_t buf_len;
	uint8_t buf_data[0];/*为了降低复杂性，目前只支持一个buffer*/
} protobuf_node_t;

typedef struct sub_data {
    list_head_t list;
    uint32_t ip;
    uint16_t port;
    uint16_t reserved;
} sub_data_t;

typedef struct proto_comm {
	uint32_t app_id;
	uint32_t debug;
	packet_t *packet;
	uint32_t state;
    uint32_t thread_id;
	longmask_t **match_mask;
    list_head_t *protobuf_head;/*用于跨包匹配的buf*/
} proto_comm_t;

static inline protobuf_node_t *protobuf_find(list_head_t *head, uint32_t engine_id)
{
	list_head_t *p;

	list_for_each(p, head) {
		protobuf_node_t *node = list_entry(p, protobuf_node_t, list);
		if (node->engine_id == engine_id) {
			return node;
		}
	}
	return NULL;
}

static inline int32_t protobuf_setbuf(list_head_t *head, uint32_t engine_id,
									  uint32_t len, void *data)
{
	protobuf_node_t *node;

	node = protobuf_find(head, engine_id);
	if (node != NULL && node->buf_len < len) {
		/*如果buf_len足够，就不必再分配空间*/
		node = realloc(node, sizeof(protobuf_node_t) + len);
		if (node == NULL) {
			return -NO_SPACE_ERROR;
		}
		node->buf_len = len;
	}

	if (node == NULL) {
		node = zmalloc(protobuf_node_t *, sizeof(protobuf_node_t) + len);
		if (node == NULL) {
			return -NO_SPACE_ERROR;
		}
		node->buf_len = len;
		list_add_tail(&node->list, head);
	}
	node->engine_id = engine_id;
	memcpy(node->buf_data, data, len);

	return 0;
}

static inline int32_t protobuf_setmask(list_head_t *head, uint32_t engine_id,
									   int32_t app_id, longmask_t *mask)
{
	protobuf_node_t *node;
	int32_t i;
	node = protobuf_find(head, engine_id);
	if (node == NULL) {
		node = zmalloc(protobuf_node_t *, sizeof(protobuf_node_t));
		if (node == NULL) {
			return -NO_SPACE_ERROR;
		} else {
			list_add_tail(&node->list, head);
		}
	}

	node->match_mask = longmask_create(mask->bit_num);

	if (node->match_mask == NULL) {
		list_del(&node->list);
		free(node);
		return -NO_SPACE_ERROR;
	}
	longmask_copy(node->match_mask, mask);

	for (i=0; i<app_id; i++) {
		longmask_bit_clr(node->match_mask, i);
	}

	return 0;
}

static inline void protobuf_destroy(list_head_t *head)
{
	list_head_t *p, *tmp;

	list_for_each_safe(p, tmp, head) {
		protobuf_node_t *node = list_entry(p, protobuf_node_t, list);
		list_del(&node->list);
		if (node->match_mask) {
			longmask_destroy(node->match_mask);
		}
		free(node);
	}
}

#endif
