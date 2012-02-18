#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <pthread.h>
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
#include "hash_table.h"
#include "snort_dfa/str_search.h"

//#define PID_TABLE_BUCKET_NUM (1<<16 - 1)
#define PSTR_TABLE_BUCKET_NUM ((1<<16)-1)
#define RID_TABLE_BUCKET_NUM ((1<<10)-1)
#define PID_ARRAY_INIT_NUM  (500)
#define PID_ARRAY_INCR_STEP (100)
#define MAX_DFA_RESULT     (16)
#define MAX_TID_RESULT     (32)
#define TIDHD_MASK_BIT_NUM (1024)

static int32_t sde_engine_init_global(module_info_t *this);
static int32_t sde_engine_init_local(module_info_t *this, uint32_t thread_id);
static int32_t sde_engine_process(module_info_t *this, void *data);
static int32_t sde_engine_fini_local(module_info_t *this, uint32_t thread_id);
static int32_t sde_engine_fini_global(module_info_t *this);

static log_t *ptlog_p;
static pthread_key_t key;

typedef struct {
    uint32_t id;
    uint32_t index;
} pid_result_t;

typedef struct {
    int32_t min;
    int32_t max;
    uint32_t tid;/*匹配的字符串偏移规则id*/
} range_t;

typedef struct {
    uint32_t range_num;
    range_t *ranges;/*相同的pattern，如果范围有重叠，可能有预想不到的后果，这个可能要深入dfa代码研究*/
} range_head_t;

typedef struct pattern_head {
    uint32_t len;
    uint8_t *value;
} pattern_head_t;

typedef struct content_head {
    uint32_t len;
    uint8_t *value;
} content_head_t;

module_ops_t sde_engine_ops = {
    .init_global = sde_engine_init_global,
    .init_local = sde_engine_init_local,
	.start = NULL,
	.process = sde_engine_process,
	.result_get = NULL,
	.result_free = NULL,
	.fini_global = sde_engine_fini_global,
	.fini_local = sde_engine_fini_local,
};

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

typedef struct hash_pstr_info {
    uint64_t graph_mask;
    pattern_head_t pat_head;
    range_head_t range_head;
} hash_pstr_info_t;

typedef struct hash_tid2rid_info {
    uint32_t proto_id;
    uint32_t tid_num;
    uint32_t *tid;
} hash_tid2rid_info_t;

typedef struct dfa_pattern_range {
    int16_t min;
    int16_t max;
} dfa_pattern_range_t;

typedef struct dfa_graph_info {
    uint32_t pid_num;
    uint32_t current_pid;
    uint32_t pattern_range_num;
    dfa_pattern_range_t *pattern_ranges;
    void *dfa_instance;
    range_head_t *pid2tid_array;
} dfa_graph_info_t;

typedef struct info_global {
	sf_proto_conf_t *conf;
	uint32_t sde_engine_id;
    uint32_t graph_num;
    uint32_t current_tid;/*为简化处理，所有图公用tid*/
    hash_table_hd_t *pstr_hd;/*pattern中的第一个字符串为key的hash表，添加时使用*/
    hash_table_hd_t *tid2rid_hd;/*tid的组合与rule id的映射关系表*/
    dfa_graph_info_t *graph_info;/*每个图相关的信息及对应的pid table*/
    longmask_t *tidhd_idmask;
} info_global_t;

typedef struct info_local {
    uint32_t current_graph;
    uint32_t pid_index;
    uint32_t tid_index;
    pid_result_t **pid_result;/*每个图都有独立的pid*/
    uint32_t *tid_result;/*所有图的tid是统一分配的*/
    content_head_t *content_hd;
    longmask_t *proto_idmask;
} info_local_t;

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

static void __fetch_sde_key(common_data_t *data, list_head_t *head, range_head_t *range_hd)
{
    char buf[SDE_KEY_MAX_LEN+1];
    char *p, *q, *last;
    uint32_t count, len;
    int i, j;

    j = 0;
    while(1) {
        count = 1;
        p = data->key;
        while (p != NULL) {
            p = strchr(p, SDE_KEY_TOKEN);
            count++;
            if (p != NULL) {
                p++;
            }
        }
        range_hd[j].ranges = zmalloc(range_t *, sizeof(range_t) * count);
        assert(range_hd[j].ranges);
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
            data = list_entry(data->list.next, common_data_t, list);
        } else {
            break;
        }
    }
}

static int32_t pid2tid_array_create(dfa_graph_info_t *graph_info)
{
    graph_info->pid2tid_array = zmalloc(range_head_t *, sizeof(range_head_t) * PID_ARRAY_INIT_NUM);
    assert(graph_info->pid2tid_array);
    graph_info->pid_num = PID_ARRAY_INIT_NUM;
    return 0;
}

static int32_t pid2tid_array_insert(dfa_graph_info_t *graph_info, range_t *range)
{
    //printf("current_id=%d, pid_num=%d\n", graph_info->current_pid, graph_info->pid_num);
    range_head_t *range_hd;
    range_t *ranges;

    if (graph_info->current_pid >= graph_info->pid_num) {
        range_head_t *array;
        array = realloc(graph_info->pid2tid_array, sizeof(range_head_t) * (graph_info->pid_num + PID_ARRAY_INCR_STEP));
        assert(array);
        graph_info->pid_num += PID_ARRAY_INCR_STEP;
        graph_info->pid2tid_array = array;
    }
    range_hd = &graph_info->pid2tid_array[graph_info->current_pid];
    ranges = realloc(range_hd->ranges, sizeof(range_t) * (range_hd->range_num + 1));
    assert(ranges);
    memcpy(&ranges[range_hd->range_num], range, sizeof(range_t));
    range_hd->ranges = ranges;
    range_hd->range_num++;
    return 0;
}

static inline int32_t pid2tid_array_search(dfa_graph_info_t *graph_info, pid_result_t *pid_result,
                                    uint32_t *tid_result, uint32_t *tid_index, uint32_t pkt_size)
{
    uint32_t pid = pid_result->id;
    uint32_t offset = pid_result->index;
    uint32_t min, max;
    uint32_t i;
    range_head_t *range_hd;
    range_t *range;

    assert(pid < graph_info->current_pid);
    range_hd = &graph_info->pid2tid_array[pid];

    for (i=0; i<range_hd->range_num; i++) {
        range = &range_hd->ranges[i];
        min = range->min >= 0 ? (uint32_t )range->min : (uint32_t)(range->min + pkt_size);
        max = range->max >= 0 ? (uint32_t )range->max : (uint32_t)(range->max + pkt_size);

        if (offset >= min && offset <= max) {
            assert(*tid_index < MAX_TID_RESULT);
            tid_result[*tid_index] = range->tid;
            (*tid_index)++;
            if (*tid_index >= MAX_TID_RESULT) {
                return -NO_SPACE_ERROR;
            }
        }
    }
    return 0;
}

static void pid2tid_array_destroy(dfa_graph_info_t *graph_info)
{
    if (graph_info->pid2tid_array) {
        free(graph_info->pid2tid_array);
    }
}


static inline uint32_t __pstr_table_hash(pattern_head_t *pattern_hd)
{
    uint8_t *str;
    uint32_t hash = 0;
    uint32_t seed[] = {23, 19, 17, 13, 9, 11, 3};
    uint32_t seed_num = sizeof(seed)/sizeof(seed[0]);
    uint32_t i;

    str = pattern_hd->value;

    for (i=0; i<pattern_hd->len; i++) {
        hash += str[i] * seed[i%seed_num];
    }
    hash = hash << 8;
    hash = ((pattern_hd->len & 0xff) | hash) & PSTR_TABLE_BUCKET_NUM;
    return hash;
}

static int32_t __pstr_item_compare(void *this, void *user_data, void *table_item)
{
    hash_pstr_info_t *table_node;
    pattern_head_t *user_pat_hd;

    table_node = (hash_pstr_info_t *)table_item;
    user_pat_hd = (pattern_head_t *)user_data;

    if (table_node->pat_head.len == user_pat_hd->len &&
            memcmp(table_node->pat_head.value, user_pat_hd->value, user_pat_hd->len) == 0) {
        return 0;
    } else {
        return 1;
    }
}

static inline int32_t __get_true_pos(int32_t pos, packet_t *packet)
{
    if (pos < 0) {
        return packet->app_offset + packet->real_applen + pos;
    } else {
        return packet->app_offset + pos;
    }
}

static hash_table_hd_t *pstr_table_create()
{
    return hash_table_init(PSTR_TABLE_BUCKET_NUM, MUTEX);
}

static void * pstr_table_search(hash_table_hd_t *hd, pattern_head_t *pat)
{
    uint32_t hash = __pstr_table_hash(pat);
    return hash_table_search(hd, hash, NULL, __pstr_item_compare, NULL, pat);
}

static int32_t pstr_item_insert_range(hash_pstr_info_t *node, range_t *range,
                                    uint32_t *current_tid, uint32_t graph_id)
{
    range_head_t *table_range_hd;
    range_t *ranges;

    table_range_hd = &node->range_head;
    ranges = table_range_hd->ranges;
    ranges = realloc(ranges,
            (table_range_hd->range_num + 1) * sizeof(range_t));
    if (ranges == NULL) {
        return -NO_SPACE_ERROR;
    }
    range->tid = (*current_tid)++;
    memcpy(&ranges[table_range_hd->range_num], range, sizeof(range_t));
    table_range_hd->ranges = ranges;
    table_range_hd->range_num++;

    node->graph_mask |= 1 << graph_id;
    return 0;
}

static hash_pstr_info_t *pstr_table_create_insert_pattern(hash_table_hd_t *hd, pattern_head_t *pat_head)
{
    hash_pstr_info_t *node;

    node = zmalloc(hash_pstr_info_t *, sizeof(hash_pstr_info_t));
    assert(node);

    memcpy(&node->pat_head, pat_head, sizeof(pattern_head_t));

    assert(hash_table_insert(hd, __pstr_table_hash(pat_head), node) == 0);
    return node;
}

static void pstr_table_destroy(hash_table_hd_t *hd)
{
    int32_t status;
    uint32_t i;

    hash_pstr_info_t *info;
    for (i=0; i<hd->bucket_num; i++) {
        hash_table_one_bucket_for_each(hd, i, info) {
            if(info->pat_head.value) {
                free(info->pat_head.value);
            }
            if (info->range_head.ranges) {
                free(info->range_head.ranges);
            }
            if ((status = hash_table_remove(hd, i, info)) != 0) {
                log_error(ptlog_p, "hash_table_remove error, status %d\n", status);
            }
            free(info);
        }
    }
}

static uint32_t pstr_get_graph_id(info_global_t *gp, pattern_head_t *pat_head, range_t *range)
{
    uint32_t i, j;
    dfa_graph_info_t *info;

    for (i=0; i<gp->graph_num; i++) {
        info = &gp->graph_info[i];
        for (j=0; j<info->pattern_range_num; j++) {
            if (info->pattern_ranges[j].min <= range->min &&
                info->pattern_ranges[j].max >= range->max) {
                return i;
            }
        }
    }
    return i-1;/*default*/
}


static int __tid_sort_cb(const void *p1, const void *p2)
{
    int32_t p1v = *(int32_t *)p1;
    int32_t p2v = *(int32_t *)p2;
    return (p1v - p2v);
}

static uint32_t __tid2rid_table_hash(uint32_t *tid, uint32_t tid_num)
{
    return tid[0] % RID_TABLE_BUCKET_NUM;
}


static hash_table_hd_t *tid2rid_table_create()
{
    return hash_table_init(RID_TABLE_BUCKET_NUM, MUTEX);
}

static int32_t tid2rid_table_search_tid(hash_table_hd_t *hd, uint32_t *tid, uint32_t tid_num)
{
    hash_tid2rid_info_t *info;
    uint32_t hash = __tid2rid_table_hash(tid, tid_num);

    hash_table_one_bucket_for_each(hd, hash, info) {
        if(info->tid_num == tid_num) {
            return memcmp(info->tid, tid, tid_num * sizeof(uint32_t));
        }
    }
    return -ITEM_NOT_FOUND;
}

static int32_t tid2rid_table_insert(hash_table_hd_t *hd, uint32_t proto_id, uint32_t *tid, uint32_t tid_num)
{
    hash_tid2rid_info_t *info;
    uint32_t hash;
    uint32_t i;

    hash = __tid2rid_table_hash(tid, tid_num);
    info = zmalloc(hash_tid2rid_info_t *, sizeof(hash_tid2rid_info_t));
    if (info == NULL) {
        return -NO_SPACE_ERROR;
    }
    info->proto_id = proto_id;
    info->tid = zmalloc(uint32_t *, sizeof(uint32_t) * tid_num);
    assert(info->tid);
    memcpy(info->tid, tid, sizeof(uint32_t) * tid_num);
    log_print(ptlog_p, "proto_id:%d, tid: ", proto_id);
    for (i=0; i<tid_num; i++) {
        log_print(ptlog_p, "%d ", tid[i]);
    }
    log_print(ptlog_p, "\n");
    info->tid_num = tid_num;
    return hash_table_insert(hd, hash, info);
}

static int32_t __tid2rid_search_cmp_cb(void *this, void *user_data, void *table_item)
{
    hash_tid2rid_info_t *info;
    uint32_t *this_tid = (uint32_t *)this;
    uint32_t this_tidnum = *(uint32_t *)user_data;
    uint32_t match_num = 0;
    uint32_t i, j;

    info = (hash_tid2rid_info_t *)table_item;
    for (i=0, j=0; i<info->tid_num; i++) {
        for (; j<this_tidnum; j++) {
            if (this_tid[j] == info->tid[i]) {
                match_num++;
                break;
            }
        }
    }
    return (info->tid_num == match_num) ? 0 : 1;

}
static int32_t tid2rid_table_search(hash_table_hd_t *hd, uint32_t *tid, uint32_t tid_num)
{
    uint32_t hash;
    hash_tid2rid_info_t *info;

    hash = __tid2rid_table_hash(tid, tid_num);
    info = hash_table_search(hd, hash, NULL, __tid2rid_search_cmp_cb, tid, &tid_num);
    return (info == NULL)? -1 : (int32_t)(info->proto_id);
}

static void tid2rid_table_destroy(hash_table_hd_t *hd)
{
    int32_t status;
    uint32_t i;
    hash_tid2rid_info_t  *info;

    for (i=0; i<hd->bucket_num; i++) {
        hash_table_one_bucket_for_each(hd, i, info) {
            if ((status = hash_table_remove(hd, i, info)) != 0) {
                log_error(ptlog_p, "hash_table_remove error, status %d\n", status);
            }
            free(info->tid);
            free(info);
        }
    }
}

static void __handle_sde_rule(info_global_t *gp, uint32_t proto_id, range_head_t *range_hd, char **pp, uint32_t total_num)
{
    uint32_t i, j, k, found;
    uint32_t *tid_id_record, *tid_record;
    int32_t status;
    int32_t new_node;
    uint32_t graph_id;
    uint64_t graph_mask;
    pattern_head_t pattern_hd;
    hash_pstr_info_t *node;

    assert(range_hd->range_num > 0);

    tid_id_record = zmalloc(uint32_t *, sizeof(uint32_t) * total_num);
    assert(tid_id_record);
    tid_record = zmalloc(uint32_t *, sizeof(uint32_t) * total_num);
    assert(tid_record);

    assert((sizeof(graph_mask) * 8) > gp->graph_num);
    for (i=0; i<total_num; i++) {
        new_node = 0;
        pattern_hd.value = zmalloc(uint8_t *, strlen(pp[i]));
        assert(pattern_hd.value);
        assert(__change_format_to_dst((unsigned char *)pattern_hd.value, pp[i], &pattern_hd.len) == 0);
        node = pstr_table_search(gp->pstr_hd, &pattern_hd);
        if (node == NULL) {
            node = pstr_table_create_insert_pattern(gp->pstr_hd, &pattern_hd);
            assert(node);
            graph_mask = 0;
            new_node = 1;
        }else {
            graph_mask = node->graph_mask;
        }
        range_head_t *table_range = &node->range_head;
        assert(table_range);
        for (j=0; j<range_hd[i].range_num; j++) {
            found = 0;
            for (k=0; k<table_range->range_num; k++) {
                if (range_hd[i].ranges[j].min == table_range->ranges[k].min &&
                        range_hd[i].ranges[j].max == table_range->ranges[k].max) {
                    found = 1;
                    break;
                }
            }
            if (found) {
                range_hd[i].ranges[j].tid = table_range->ranges[j].tid;
            } else {
                graph_id = pstr_get_graph_id(gp,
                                            &pattern_hd, &range_hd[i].ranges[j]);
                dfa_graph_info_t *graph_info = &gp->graph_info[graph_id];

                status = pstr_item_insert_range(node, &range_hd[i].ranges[j],
                                                &gp->current_tid, graph_id);
                pid2tid_array_insert(graph_info, &range_hd[i].ranges[j]);
                if ((graph_mask & (1<<graph_id)) == 0) {
                    search_api->search_instance_add(graph_info->dfa_instance, (const char *)pattern_hd.value,
                                                    (int)pattern_hd.len, graph_info->current_pid);
                    graph_info->current_pid++;
                }

                log_debug(ptlog_p, "range: %d~%d, content: %s, tid %d\n",
                        range_hd[i].ranges[j].min, range_hd[i].ranges[j].max,
                        pp[i], range_hd[i].ranges[j].tid);
                assert(status == 0);
            }
        }
        if (!new_node) {
            free(pattern_hd.value);
        }
    }

    /*开始回溯法，取得所有的范围组合,形成tid和rid(proto_id)的对应关系*/
    i = 0;
    for (j=0; j<total_num; j++) {
        tid_id_record[j] = -1;
    }
    while ((int)i >= 0) {
        tid_id_record[i]++;
        //printf("i=%d, id_rec=%d, range_num %d, total_num=%d\n", i, tid_id_record[i], range_hd[i].range_num, total_num);
        if (tid_id_record[i] < range_hd[i].range_num) {
            tid_record[i] = range_hd[i].ranges[tid_id_record[i]].tid;
            if (i == total_num - 1) {
                if (tid2rid_table_search_tid(gp->tid2rid_hd, tid_record, total_num) == 0) {
                    log_error(ptlog_p, "rid exist, omitted\n");
                } else {
                    qsort(tid_record, total_num, sizeof(uint32_t), __tid_sort_cb);
                    status = tid2rid_table_insert(gp->tid2rid_hd, proto_id, tid_record, total_num);
                    assert(status == 0);
                    longmask_bit_set(gp->tidhd_idmask, tid_record[0]);
                }
            } else {
                i++;
                tid_id_record[i] = -1;
            }
        } else {
            i--;
        }
    }
    free(tid_record);
    free(tid_id_record);
}

static void __handle_sde_string(info_global_t *gp, uint32_t proto_id, common_data_t *data,
                                list_head_t *head,
                                char **pp, range_head_t *range_hd,
                                uint32_t current, uint32_t total_num)
{
    common_data_t *next;

    if (current >= total_num) {
        __handle_sde_rule(gp, proto_id, range_hd, pp, total_num);
   } else {
        if (pp[current] != NULL) {
            free(pp[current]);
            pp[current] = NULL;
        }
        __get_next_value_from_rule(data->value, &pp[current]);
       do {
            next = list_entry(data->list.next, common_data_t, list);
            __handle_sde_string(gp, proto_id, next, head, pp, range_hd, current+1, total_num);
            __get_next_value_from_rule(data->value, &pp[current]);
        } while (pp[current] != NULL);
    }
}

static int32_t __parse_sde_proto_conf(info_global_t *gp, uint32_t proto_id, common_data_head_t *head)
{
    common_data_head_t *p;
    common_data_t *data;
    range_head_t *range_hd;
    char **pp;
    uint32_t i;

    for (p=head; p!=NULL; p=p->next) {
        if (p->item_num != 0) {
            data = list_entry(p->list.next, common_data_t, list);
            pp = (char **)malloc(sizeof(char *) * p->item_num);
            assert(pp);
            for (i=0; i<p->item_num; i++) {
                pp[i] = NULL;
            }
            range_hd = zmalloc(range_head_t *, sizeof(range_head_t) * p->item_num);
            assert(range_hd);

            __fetch_sde_key(data, &p->list, range_hd);
#if 0
            for (i=0; i<p->item_num; i++) {
                uint32_t j;
                for (j=0; j<range_hd[i].range_num; j++) {
                    log_debug(ptlog_p, "min=%d, max=%d\n",
                            range_hd[i].ranges[j].min, range_hd[i].ranges[j].max);
                }
            }
#endif
            __handle_sde_string(gp, proto_id, data, &p->list, pp, range_hd, 0, p->item_num);

            for (i=0; i<p->item_num; i++) {
                free(range_hd[i].ranges);
            }
            free(range_hd);
            for (i=0; i<p->item_num; i++) {
                if (pp[i] != NULL) {
                    free(pp[i]);
                }
            }
            free(pp);
        }
    }
    return 0;
}

static int32_t __sde_conf_read(info_global_t *gp, sf_proto_conf_t *conf, uint32_t sde_engine_id)
{
	uint32_t i, j, status;
	proto_conf_t *protos = conf->protos;
    common_data_head_t *head_p, *hd_p;

	assert(protos);
    head_p = conf->engines[sde_engine_id].conf;

    for (i=0, hd_p = head_p; hd_p != NULL; hd_p = hd_p->next, i++) {
        common_data_t *data;
        list_head_t *p;
        dfa_graph_info_t *graph_info;
        char *cp;

        graph_info = &gp->graph_info[i];
        status = pid2tid_array_create(graph_info);
        assert(status == 0);
        graph_info->dfa_instance = search_api->search_instance_new();
        assert(graph_info->dfa_instance);
        graph_info->pattern_range_num = hd_p->item_num;
        graph_info->pattern_ranges = zmalloc(dfa_pattern_range_t *,
                                            sizeof(dfa_pattern_range_t) * hd_p->item_num);
        assert(graph_info->pattern_ranges);
        j = 0;
        list_for_each(p, &hd_p->list) {
            data = list_entry(p, common_data_t, list);
            assert(data->value);
            if (strcmp(data->value, "all") == 0) {
                graph_info->pattern_ranges[j].min = 0;
                graph_info->pattern_ranges[j].max = -1;
            } else {
                cp = strchr(data->value, DFA_PATTERN_RANGE_TOKEN);
                if (cp == NULL) {
                    graph_info->pattern_ranges[j].min = strtoull(data->value, NULL, 0);
                    assert(errno == 0);
                    graph_info->pattern_ranges[j].max = graph_info->pattern_ranges[j].min;
                } else {
                    char tmp;
                    tmp = *cp;
                    *cp = '\0';
                    graph_info->pattern_ranges[j].min = strtoull(data->value, NULL, 0);
                    assert(errno == 0);
                    graph_info->pattern_ranges[j].max = strtoull(cp+1, NULL, 0);
                    assert(errno == 0);
                    *cp = tmp;
                }
            }
            log_debug(ptlog_p, "graph_min %d, max %d\n", graph_info->pattern_ranges[j].min,
                    graph_info->pattern_ranges[j].max);
            j++;
        }
    }

	for (i=0; i<conf->total_proto_num; i++) {
		if ((conf->protos[i].engine_mask & (1<<sde_engine_id)) == 0) {
			continue;
		}
		if (__parse_sde_proto_conf(gp, i, &conf->protos[i].engine_head[sde_engine_id]) != 0) {
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
    common_data_head_t *head_p, *hd_p;
	int32_t status;
    uint32_t i, graph_num = 0;

	info = zmalloc(info_global_t *, sizeof(info_global_t));
	assert(info);

	info->conf = conf;
	ptlog_p = conf->proto_log;

	info->sde_engine_id = engine_id_get(conf, "sde");
	assert(info->sde_engine_id != INVALID_ENGINE_ID);

    info->pstr_hd = pstr_table_create();
    assert(info->pstr_hd);

    info->tid2rid_hd = tid2rid_table_create();
    assert(info->tid2rid_hd);

    info->tidhd_idmask = longmask_create(TIDHD_MASK_BIT_NUM);
    assert(info->tidhd_idmask);
    /*we need read sde global conf first*/
    head_p = conf->engines[info->sde_engine_id].conf;
    hd_p = head_p;
    while(hd_p) {
        graph_num++;
        hd_p = hd_p->next;
    }
    info->graph_info = zmalloc(dfa_graph_info_t *, sizeof(dfa_graph_info_t ) * graph_num);
    assert(info->graph_info);

    info->graph_num = graph_num;

    status = __sde_conf_read(info, conf, info->sde_engine_id);
	assert(status == 0);

    log_debug(ptlog_p, "graph num is %d\n", (int)graph_num);
    for (i=0; i<graph_num; i++) {
        search_api->search_instance_prep(info->graph_info[i].dfa_instance);
    }
    this->pub_rep = (void *)info;

    pthread_key_create(&key, NULL);
	return 0;
}

static int32_t sde_engine_init_local(module_info_t *this, uint32_t thread_id)
{
    info_local_t *lp;
    info_global_t *gp;
    uint32_t i;

    gp = (info_global_t *)this->pub_rep;

    lp = zmalloc(info_local_t *, sizeof(info_local_t));
	assert(lp);

    if (gp->graph_num) {
        lp->pid_result = zmalloc(pid_result_t **, sizeof(pid_result_t *) * gp->graph_num);
        assert(lp->pid_result);
        for (i=0; i<gp->graph_num; i++) {
            lp->pid_result[i] = zmalloc(pid_result_t *, sizeof(pid_result_t) * MAX_DFA_RESULT);
            assert(lp->pid_result[i]);
        }
        lp->content_hd = zmalloc(content_head_t *, sizeof(content_head_t) * gp->graph_num);
        assert(lp->content_hd);
        lp->tid_result = zmalloc(uint32_t *, sizeof(uint32_t) * MAX_TID_RESULT);
        assert(lp->tid_result);
    }

    lp->proto_idmask = longmask_create(gp->conf->total_proto_num);
    assert(lp->proto_idmask);
    module_priv_rep_set(this, thread_id, (void *)lp);

    pthread_setspecific(key, lp);
    return 0;
}

static int match_cb(void* id, void * tree, int index, void *data, void *neg_list)
{
    uint32_t pid;
    info_local_t *lp;
    pid_result_t *result;

    pid = *(uint32_t *)id;
    lp = (info_local_t *)pthread_getspecific(key);
    assert(lp->pid_index < MAX_DFA_RESULT);
    result = &lp->pid_result[lp->current_graph][lp->pid_index++];
    result->id = pid;
    result->index = index;
    if (lp->pid_index >= MAX_DFA_RESULT) {
        /*结果已满，不再产生新的回调*/
        return 0;
    } else {
        return -1;
    }
}

static int32_t sde_engine_process(module_info_t *this, void *data)
{
	proto_comm_t *proto_comm;
    packet_t *packet;
    info_global_t *gp;
	info_local_t *lp;
    dfa_graph_info_t *graph_info;
    uint32_t i, j;
    int32_t min, max, status;
    int32_t app_id;
    uint32_t tag = 0;
    uint8_t *pattern;

	proto_comm = (proto_comm_t *)data;
    packet = proto_comm->packet;
	gp = (info_global_t *)this->pub_rep;
    lp = (info_local_t *)module_priv_rep_get(this, proto_comm->thread_id);

    lp->tid_index = 0;
    for (i=0; i<gp->graph_num; i++) {
        graph_info = &gp->graph_info[i];
        lp->current_graph = i;
        lp->pid_index = 0;
        for (j=0; j<graph_info->pattern_range_num; j++) {
            min = __get_true_pos(graph_info->pattern_ranges[j].min, packet);
            max = __get_true_pos(graph_info->pattern_ranges[j].max, packet);
            if ((min < 0) || (max < 0)) {
                log_error(ptlog_p, "range error, min=%d, max=%d, packet_size %d\n",
                            min, max, packet->len);
                continue;
            }
            if (max < packet->app_offset) {
                continue;
            }
            min = minval(packet->app_offset, (uint32_t)min);
            pattern = (uint8_t *)packet->data + min;
            max = minval(packet->app_offset + packet->real_applen, (uint32_t)max);
            search_api->search_instance_find(graph_info->dfa_instance, (const char *)pattern,
                    (uint32_t)(max - min + 1), 0, match_cb);
        }
        for (j=0; j<lp->pid_index; j++) {
            status = pid2tid_array_search(graph_info, &lp->pid_result[i][j], lp->tid_result,
                    &lp->tid_index, packet->len);
            if (status != 0) {
                log_error(ptlog_p, "Too much tid, omitted\n");
                break;
            }
        }
    }

    for (i=0; i<lp->tid_index; i++) {
        if (longmask_bit_is_set(gp->tidhd_idmask, lp->tid_result[i])) {
            app_id = tid2rid_table_search(gp->tid2rid_hd, &lp->tid_result[i], lp->tid_index - i);
            if (app_id >= 0) {
                longmask_bit_set(lp->proto_idmask, (uint32_t)app_id);
            }
        }
    }

    longmask_op_and(proto_comm->match_mask[gp->sde_engine_id], lp->proto_idmask);
	app_id = handle_engine_mask(gp->conf, proto_comm->match_mask[gp->sde_engine_id],
								proto_comm->match_mask, gp->sde_engine_id,
								&tag, 1);
	longmask_all_clr(proto_comm->match_mask[gp->sde_engine_id]);

	if (app_id < 0) {
		/*处理本引擎开始的mask*/
		app_id = handle_engine_mask(gp->conf, lp->proto_idmask, proto_comm->match_mask,
									gp->sde_engine_id, &tag, 0);
	}
	if (app_id >= 0) {
		proto_comm->app_id = app_id;
		proto_comm->state = gp->conf->final_state;
	} else {
		proto_comm->app_id = INVALID_PROTO_ID;
	}

    return tag;
}

static int32_t sde_engine_fini_local(module_info_t *this, uint32_t thread_id)
{
	info_local_t *lp;
    info_global_t *gp;
    uint32_t i;

    lp = (info_local_t *)module_priv_rep_get(this, thread_id);
    gp = (info_global_t *)this->pub_rep;
    if (lp->pid_result) {
        for (i=0; i<gp->graph_num; i++) {
            free(lp->pid_result[i]);
        }
        free(lp->pid_result);
    }
    if (lp->tid_result) {
        free(lp->tid_result);
    }
    if (lp->content_hd) {
        free(lp->content_hd);
    }
	free(lp);
	return 0;
}
static int32_t sde_engine_fini_global(module_info_t *this)
{
	info_global_t *info;
    uint32_t i, dfa_num;

	info = (info_global_t *)this->pub_rep;

    pstr_table_destroy(info->pstr_hd);
    tid2rid_table_destroy(info->tid2rid_hd);
    longmask_destroy(info->tidhd_idmask);
    dfa_num = info->graph_num;
    if (dfa_num > 0) {
        for (i=0; i<dfa_num; i++) {
            search_api->search_instance_free(info->graph_info[i].dfa_instance);
            pid2tid_array_destroy(&info->graph_info[i]);
        }
        free(info->graph_info);
    }

    if (info) {
		free(info);
	}

    pthread_key_delete(key);
	return 0;
}

