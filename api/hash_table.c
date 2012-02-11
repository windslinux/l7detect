#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "helper.h"
#include "common.h"
#include "hash_table.h"

int32_t __lock_init(hash_table_lock_t *lock, uint32_t bucket_num, uint32_t lock_type)
{
	int32_t status;
	uint32_t i;

	switch (lock_type) {
	case SPINLOCK:
		for (i=0; i<bucket_num; i++) {
			status = spin_init(&lock[i].spinlock, 0);
			assert(status == 0);
		}
		break;
	case MUTEX:
		for (i=0; i<bucket_num; i++) {
			status = mutex_init(&lock[i].mutexlock, NULL);
			assert(status == 0);
		}
		break;
	case RWLOCK:
		for (i=0; i<bucket_num; i++) {
			status = rwlock_init(&lock[i].rwlock, NULL);
			assert(status == 0);
		}
		break;
	default:
		return -1;
		break;
	}
	return 0;
}

hash_table_hd_t* hash_table_init(uint32_t bucket_num, uint32_t lock_type)
{
	uint32_t i;
	assert (lock_type < LOCK_TYPE_INVALID);

	hash_table_hd_t *hd = malloc(sizeof(hash_table_hd_t) + sizeof(list_head_t) * bucket_num);
	assert(hd);
	memset(hd, 0, sizeof(hash_table_hd_t));

	hd->bucket_num = bucket_num;
	hd->lock_type = lock_type;

	hd->lock = malloc(sizeof(hash_table_lock_t) * bucket_num);
	assert(hd->lock);

	assert(__lock_init(hd->lock, bucket_num, lock_type) == 0);

	for (i=0; i<bucket_num; i++) {
		LIST_HEAD_INIT(&hd->head[i]);
	}

	return hd;
}

int32_t hash_table_lock(hash_table_hd_t* hd, uint32_t hash, uint32_t lock_type)
{
	int32_t status = 0;
	assert(hash < hd->bucket_num);

	switch (hd->lock_type) {
	case SPINLOCK:
		status = spin_lock(&hd->lock[hash].spinlock);
		break;
	case MUTEX:
		status = mutex_lock(&hd->lock[hash].mutexlock);
		break;
	case RWLOCK:
		if (lock_type == READ_LOCK) {
			status = rwlock_rdlock(&hd->lock[hash].rwlock);
		} else {
			status = rwlock_wrlock(&hd->lock[hash].rwlock);
		}
		break;
	default:
		status = -INVALID_PARAM;
		break;
	}
	return status;
}

int32_t hash_table_unlock(hash_table_hd_t* hd, uint32_t hash, uint32_t lock_type)
{
	int32_t status = 0;
	assert(hash < hd->bucket_num);

	switch (hd->lock_type) {
	case SPINLOCK:
		status = spin_unlock(&hd->lock[hash].spinlock);
		break;
	case MUTEX:
		status = mutex_unlock(&hd->lock[hash].mutexlock);
		break;
	case RWLOCK:
		status = rwlock_unlock(&hd->lock[hash].rwlock);
		break;
	default:
		status = -INVALID_PARAM;
		break;
	}
	return status;
}

int32_t hash_table_insert(hash_table_hd_t* hd, uint32_t hash, void *item)
{
	assert(hash < hd->bucket_num);

	hash_node_t *node = (hash_node_t *)malloc(sizeof(hash_node_t));
	if_error_return(node != NULL, -NO_SPACE_ERROR);

	node->data = item;
	list_add_tail(&node->list, &hd->head[hash]);
	return 0;
}

void* hash_table_search(hash_table_hd_t* hd, uint32_t hash, void *pos, hash_table_compare_handle_t compare,
						   void *this, void *user_data)
{
	list_head_t *p;
	uint32_t found = 0;
	assert(hash < hd->bucket_num);

	list_for_each(p, &hd->head[hash]) {
		hash_node_t *node = list_entry(p, hash_node_t, list);
		if ((pos != NULL) && !found) {
			if (pos == node->data) {
				/*跳过这个节点，从下一个开始*/
				found = 1;
			}
			continue;
		}
		if (compare == NULL || compare(this, user_data, node->data) == 0) {
			return node->data;
		}
	}
	return NULL;
}

int32_t hash_table_remove(hash_table_hd_t* hd, uint32_t hash, void *pos)
{
	list_head_t *p, *n;

	assert(hash < hd->bucket_num);
	list_for_each_safe(p, n, &hd->head[hash]) {
		hash_node_t *node = list_entry(p, hash_node_t, list);
		if (pos == node->data) {
			list_del(&node->list);
			free(node);
			return 0;
		}
	}
	return -ITEM_NOT_FOUND;
}

void hash_table_fini(hash_table_hd_t** head_pp)
{
	hash_table_hd_t *head_p = *head_pp;
	if (head_p->lock) {
		free(head_p->lock);
	}
	free(head_p);
	*head_pp = NULL;
}

