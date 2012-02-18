#ifndef __HELPER_H__
#define __HELPER_H__

#ifdef __linux__
#include <arpa/inet.h>
#endif
#include "log.h"

#define align(x, a) (((x) + (a) - 1) & ~((a) - 1))
#define minval(a,b) ((a) < (b) ? (a):(b))
/**
 *@brief 交换a,b的值
*/
#define swap(a, b) \
    do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)

#ifndef offsetof
#define offsetof(type, member) ( (unsigned long) & ((type*)0) -> member )
#endif

#define container_of(ptr, type, member) ({                      \
            const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
            (type *)( (char *)__mptr - offsetof(type,member) );})

enum format_print_type {
    FORMAT_PRINT_WITH_HEAD,
    FORMAT_PRINT_SIMPLE,
};

void list_format_print_head(log_t *log, int width);
void list_format_print_body(log_t *log, void *list, int width, int length, int index, int type);
void list_format_print_buffer(log_t *log, void *list, int width, int length, int type);


#define zmalloc(type, size) ({			\
		type ptr = (type)(malloc(size));			\
		if (ptr != 0)							\
			memset(ptr, 0, size);				\
		ptr;									\
		} )

typedef struct kv_table {
	char *key;
	int value;
} kv_table_t;

int kv_get_index_from_key(kv_table_t *table, char *key);
int kv_get_index_from_value(kv_table_t *table, int value);


#endif
