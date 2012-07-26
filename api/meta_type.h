#ifndef __META_TYPE_H__
#define __META_TYPE_H__

#include <common.h>

enum {
    META_TYPE_INVALID,
	META_TYPE_FF, /*type:meta_ff_t*/
    META_TYPE_TUPLE_INFO,
};

typedef struct meta_ff{
    uint32_t ip;
    uint32_t app_type;
    uint16_t port;
} meta_ff_t;

typedef struct meta_tuple_info {
	uint32_t sip, dip;
	uint16_t sport, dport;
	uint32_t protocol:8;
    uint32_t dir:8;
    uint32_t reserved:16;
} meta_tuple_info_t;


#endif
