#ifndef __META_TYPE_H__
#define __META_TYPE_H__

#include <common.h>

enum {
	META_TYPE_FF, /*type:meta_ff_t*/
};

typedef struct meta_ff{
    uint32_t ip;
    uint32_t app_type;
    uint16_t port;
} meta_ff_t;


#endif
