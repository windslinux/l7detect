#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include "common.h"
#include "decap.h"
#include "plugin.h"
#include "module_manage.h"
#include "conf.h"
#include "log.h"
#include "parser.h"
#include "helper.h"

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "ldlua.h"
#include "engine_comm.h"

static int32_t sde_engine_init_global(module_info_t *this);
static int32_t sde_engine_process(module_info_t *this, void *data);
static int32_t sde_engine_fini_global(module_info_t *this);

static log_t *ptlog_p;

typedef struct {
    int16_t min;
    int32_t max;
} range_t;

typedef struct {
    uint32_t range_num;
    range_t *ranges;
} range_head_t;

typedef struct pattern_head {
    uint32_t len;
    uint8_t *value;
} pattern_head_t;
module_ops_t sde_engine_ops = {
	.init_global = sde_engine_init_global,
    .init_local = NULL,
	.start = NULL,
	.process = sde_engine_process,
	.result_get = NULL,
	.result_free = NULL,
	.fini_global = sde_engine_fini_global,
	.fini_local = NULL,
};

typedef struct info_global {
	sf_proto_conf_t *conf;
	uint32_t sde_engine_id;
} info_global_t;

typedef struct key_offset {
    uint8_t key;
    uint8_t reserved;
    uint16_t offset;
} key_offset_t;

typedef struct strbuf_list{
    list_head_t init_list;
    list_head_t process_list;
    key_offset_t value;
} strbuf_list_t;

enum {
    HEX_MODE,
    STRING_MODE,
    SHIFT_MODE,
};

#define __change_mode(cur) do {    \
    mode = cur;                         \
} while(0)

#define __change_mode_clr(cur) do {    \
    mode = cur;                            \
    j = 0;                                  \
} while(0)

#define PROCESS do {                                                \
    if ((status = __handle_pattern_buf(p, buf, &j, mode)) < 0) {      \
        FAIL;                                                       \
    } else {                                                        \
        p += status;                                                \
    }                                                               \
} while (0)

#define FAIL    do {                                            \
    printf("src=%s, pos %d, status %d\n", src, i+1, status);      \
    return -1;                                                  \
} while(0)

static int __handle_pattern_buf(unsigned char *p, char *buf, uint32_t *j, int mode)
{
    if (*j <= 0) {
        return 0;
    }
    if (mode == HEX_MODE) {
        if (*j == 2) {
            *j = 0;
            if (isxdigit(buf[0]) && isxdigit(buf[1])) {
                unsigned long int value;
                value = strtoull(buf, NULL, 16);
                *p = (value) & 0xff;
                if (errno) {
                    return errno;
                } else {
                    return 1;
                }
            } else {
                return -INVALID_PARAM;
            }
        } else {
            return 0;
        }
    }
    if (mode >= STRING_MODE) {
        if (*j != 1) {
            return -HANDLE_INCOMPLETE;
        } else {
            *p = *buf;
            *j = 0;
            return 1;
        }
    }
    return -UNKNOWN_ERROR;
}

static int __change_format_to_dst(unsigned char *dst, char *src, uint32_t *n)
{
    unsigned char *p;
    char buf[3];
    uint32_t i, j, mode;
    int32_t status;

    mode = HEX_MODE;
    buf[2] = '\0';
    for (i=0, j=0, p=dst; i<strlen(src); i++) {
        buf[j++] = src[i];
        switch(mode) {
           case HEX_MODE:
                {
                    if (isxdigit(src[i])) {
                        PROCESS;
                    } else if (src[i] == '(') {
                        j--;
                        PROCESS;
                        __change_mode(STRING_MODE);
                    } else {
                        status = -10;
                        FAIL;
                    }
                }
                break;
            case STRING_MODE:
                {
                    if (src[i] == '\\') {
                        j--;
                        __change_mode(SHIFT_MODE);
                    } else if (src[i] == ')') {
                        j--;
                        __change_mode(HEX_MODE);
                    } else {
                        PROCESS;
                    }
                }
                break;
            case SHIFT_MODE:
                {
                    PROCESS;
                    __change_mode_clr(STRING_MODE);
                }
                break;
            default:
                break;
       }
    }
    if (j!= 0) {
        j--;
        status = -HANDLE_INCOMPLETE;
        FAIL;
    }
    *n = p - dst;
    return 0;
}

static void __get_next_value_from_rule(char *key, char **pp)
{
    char *p = *pp;
    char *token, *start;
    uint32_t len;

    if (p == NULL) {
        start = key;
    } else {
        start = strstr(key, p);
        if (start != NULL) {
            start += strlen(p);
            while (*start == ' ' || *start == '\t' || *start == '|') {
                start++;
            }
            if (*start == '\0') {
                free(p);
                *pp = NULL;
                return;
            }
        } else {
			log_error(ptlog_p, "Fatal Error, quit\n");
            free(p);
            *pp = NULL;
            return;
        }
    }
    token = strchr(start, SDE_PAT_TOKEN);

    if (p != NULL) {
        free(p);
        *pp = NULL;
    }
    if (token == NULL) {
        len = strlen(start);
    } else {
        len = token - start;
    }
    p = malloc(len + 1);
    assert(p);

    strncpy(p, start, len);
    *(p+len) = '\0';
    *pp = p;
}

static void __fetch_sde_key(proto_data_t *data, list_head_t *head, range_head_t *range_hd)
{
    char buf[SDE_KEY_MAX_LEN+1];
    char *p, *q, *last;
    uint32_t count, len;
    int i, j;

    j = 0;
    while(1) {
        count = 0;
        p = data->key;
        while (p != NULL) {
            p = strchr(p, SDE_KEY_TOKEN);
            count++;
            if (p != NULL) {
                p++;
            }
        }
        range_hd[j].ranges = zmalloc(range_t *, sizeof(range_t) * count);
        assert(range_hd);
        i = 0;
        p = data->key;
        while (p != NULL) {
            last = p;
            p = strchr(p, SDE_KEY_TOKEN);
            if (p == NULL) {
                len = strlen(last);
            } else {
                len = p-last;
                p++;
            }
            memcpy(buf, last, len);
            buf[len] = '\0';
            q = strchr(buf, SDE_KEY_RANGE_TOKEN);
            if (q != NULL) {
                *q = '\0';
                range_hd[j].ranges[i].min = strtoull(buf, NULL, 0);
                assert(errno == 0);
                range_hd[j].ranges[i].max = strtoull(q+1, NULL, 0);
                assert(errno == 0);
            } else {
                range_hd[j].ranges[i].min = strtoull(buf, NULL, 0);
                assert(errno == 0);
                range_hd[j].ranges[i].max = range_hd[j].ranges[i].min;
            }
            i++;
            range_hd[j].range_num++;
            if (range_hd[j].ranges[i].min > range_hd[j].ranges[i].max) {
                swap(range_hd[j].ranges[i].min, range_hd[j].ranges[i].max);
            }
        }
        if (data->list.next != head) {
            j++;
            data = list_entry(data->list.next, proto_data_t, list);
        } else {
            break;
        }
    }
}

static void __handle_sde_rule(range_head_t *range_hd, char **pp, uint32_t total_num)
{
    uint32_t i, j;
    pattern_head_t *pattern_hd;

    pattern_hd = zmalloc(pattern_head_t *, sizeof(pattern_head_t) * total_num);
    assert(pattern_hd);

    for (i=0; i<total_num; i++) {
        pattern_hd[i].value = zmalloc(uint8_t *, strlen(pp[i]));
        assert(pattern_hd[i].value);
        assert(__change_format_to_dst((unsigned char *)pattern_hd[i].value, pp[i], &pattern_hd[i].len) == 0);

        for (j=0; j<pattern_hd[i].len; j++) {
            if (isprint(pattern_hd[i].value[j])) {
                printf("%c", pattern_hd[i].value[j]);
            } else {
                printf(" 0x%02x ", (unsigned char)pattern_hd[i].value[j]);
            }
        }
    }

    printf("\n");

    //__sde_table_add(range_hd, pattern_hd, total_num);
}

static void __handle_sde_string(proto_data_t *data, list_head_t *head, char **pp, range_head_t *range_hd,
                                uint32_t current, uint32_t total_num)
{
    proto_data_t *next;

    if (current >= total_num) {
        __handle_sde_rule(range_hd, pp, total_num);
   } else {
        if (pp[current] != NULL) {
            free(pp[current]);
            pp[current] = NULL;
        }
        __get_next_value_from_rule(data->value, &pp[current]);
       do {
            next = list_entry(data->list.next, proto_data_t, list);
            __handle_sde_string(next, head, pp, range_hd, current+1, total_num);
            __get_next_value_from_rule(data->value, &pp[current]);
        } while (pp[current] != NULL);
    }
}

static int32_t __parse_sde_proto_conf(proto_data_head_t *head)
{
    proto_data_head_t *p;
    proto_data_t *data;
    range_head_t *range_hd;
    char **pp;
    uint32_t i;

    for (p=head; p!=NULL; p=p->next) {
        if (p->item_num != 0) {
            data = list_entry(p->list.next, proto_data_t, list);
            pp = (char **)malloc(sizeof(char *) * p->item_num);
            assert(pp);
            for (i=0; i<p->item_num; i++) {
                pp[i] = NULL;
            }
            range_hd = zmalloc(range_head_t *, sizeof(range_head_t) * p->item_num);
            assert(range_hd);

            __fetch_sde_key(data, &p->list, range_hd);
            for (i=0; i<p->item_num; i++) {
                uint32_t j;
                for (j=0; j<range_hd[i].range_num; j++) {
                    printf("min=%d, max=%d\n", range_hd[i].ranges[j].min, range_hd[i].ranges[j].max);
                }
            }
            __handle_sde_string(data, &p->list, pp, range_hd, 0, p->item_num);

            for (i=0; i<p->item_num; i++) {
                if (pp[i] != NULL) {
                    free(pp[i]);
                }
                if (range_hd[i].ranges != NULL) {
                    free(range_hd[i].ranges);
                }
            }
            free(pp);
            free(range_hd);
        }
    }
    return 0;
}

static int32_t __sde_conf_read(sf_proto_conf_t *conf, uint32_t sde_engine_id)
{
	uint32_t i;
	proto_conf_t *protos = conf->protos;
	//int32_t proto_id;

	assert(protos);

	for (i=0; i<conf->total_proto_num; i++) {
		if ((conf->protos[i].engine_mask & (1<<sde_engine_id)) == 0) {
			continue;
		}
		if (__parse_sde_proto_conf(&conf->protos[i].engine_head[sde_engine_id]) != 0) {
			log_error(ptlog_p, "parse protocol [%s] error, system halt\n", conf->protos[i].name);
			exit(-1);
		}
	}
	return 0;
}

static int32_t sde_engine_init_global(module_info_t *this)
{
	sf_proto_conf_t *conf = (sf_proto_conf_t *)this->pub_rep;
	info_global_t *info;
	int32_t status;

	info = zmalloc(info_global_t *, sizeof(info_global_t));
	assert(info);

	info->conf = conf;
	ptlog_p = conf->proto_log;

	info->sde_engine_id = engine_id_get(conf, "sde");
	assert(info->sde_engine_id != INVALID_ENGINE_ID);

   	status = __sde_conf_read(conf, info->sde_engine_id);
	assert(status == 0);

	this->pub_rep = (info_global_t *)info;
	return 0;
}

static int32_t sde_engine_process(module_info_t *this, void *data)
{
    return 0;
}

static int32_t sde_engine_fini_global(module_info_t *this)
{
	info_global_t *info;

	info = (info_global_t *)this->pub_rep;

	if (info) {
		free(info);
	}
	return 0;
}

