#ifndef __HASH_TABLE_H__
#define __HASH_TABLE_H__

#include "common.h"
#include "list.h"
#include "lock.h"

enum rwlock_type{
	READ_LOCK,
	WRITE_LOCK,
};

typedef union hash_table_lock{
	mutex_t mutexlock;
	spinlock_t spinlock;
	rwlock_t rwlock;
} hash_table_lock_t;

typedef struct hash_node {
	list_head_t list;
	void *data;
} hash_node_t;

typedef struct hash_table_hd {
	uint32_t bucket_num;
	uint32_t lock_type;
	hash_table_lock_t *lock;
	list_head_t head[0];
} hash_table_hd_t;

typedef int32_t (*hash_table_compare_handle_t)(void *this, void *user_data, void *table_item);

int32_t hash_table_lock(hash_table_hd_t* hd, uint32_t hash, uint32_t lock_type);
int32_t hash_table_unlock(hash_table_hd_t* hd, uint32_t hash, uint32_t lock_type);
hash_table_hd_t* hash_table_init(uint32_t bucket_num, uint32_t lock_type);
int32_t hash_table_insert(hash_table_hd_t* hd, uint32_t hash, void *item);
void* hash_table_search(hash_table_hd_t* hd, uint32_t hash, void *pos, hash_table_compare_handle_t compare,
							   void *this, void *user_data);
int32_t hash_table_remove(hash_table_hd_t* hd, uint32_t hash, void *pos);
void hash_table_fini(hash_table_hd_t** head_p);

#define hash_table_one_bucket_for_each(hd, hash, pos)	\
	pos = NULL;										\
	while ((pos = hash_table_search(hd, hash, pos, NULL, NULL, NULL)) != NULL)



#endif



