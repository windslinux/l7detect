#ifndef __CONF_H__
#define __CONF_H__
#include <stdlib.h>
#include "common.h"
#include "list.h"
#include "lua_ci.h"
#include "log.h"

#define common_free_cb free
#define ENGINE_NAME_LEN 10
#define SESSION_CONF_NAME "session_conf"
#define SF_PROTO_CONF_NAME "proto_conf"

#define INVALID_ENGINE_ID 65535
#define INVALID_PROTO_ID 65535
#define MAX_SDE_GRAPH_RANGE  16
#define DFA_PATTERN_RANGE_TOKEN '~'

#define SDE_PAT_TOKEN   '|'
#define SDE_KEY_TOKEN   '|'
#define SDE_KEY_RANGE_TOKEN '~'
#define SDE_KEY_MAX_LEN 20
enum {
	MODE_NOT_SET,
	MODE_LIVE,
	MODE_FILE,
    MODE_SE,
};

typedef struct common_data {
    list_head_t list;
    char *key;
    char *value;
} common_data_t;

typedef struct common_data_head {
	int16_t lua_type;
    uint16_t item_num;
    struct common_data_head *next;
    list_head_t list;
} common_data_head_t;

typedef struct session_conf {
	uint32_t bucket_num;
	uint32_t session_expire_time;
	char *hash_name;
	char *session_logname;
} session_conf_t;

typedef struct proto_conf {
	char *name;
	uint32_t engine_mask;
	common_data_head_t *engine_head;
} proto_conf_t;

typedef struct detect_engine {
	char name[ENGINE_NAME_LEN];
    common_data_head_t *conf;
} detect_engine_t;

typedef struct sf_proto_conf {
	lua_State *L;
	char *app_luabuf;
	log_t *proto_log;
	uint32_t total_engine_num;
	uint32_t total_proto_num;
	uint32_t final_state;
	detect_engine_t *engines;
	proto_conf_t *protos;
} sf_proto_conf_t;

typedef struct conf {
	int mode;
	union {
		char *device;
		char *capfile;
	} u;
    uint32_t thread_num;
    uint32_t pkt_num;
    char *configfile;
	char *logfile;
	char *protofile;
	list_head_t module_conf_head;
} conf_t;

typedef void (*conf_node_free_callback)(void *data);

extern conf_t g_conf;

int32_t conf_init();
int32_t conf_read(int argc, char *argv[]);
int32_t conf_module_config_insert(char *name, void *config, conf_node_free_callback free_cb);
void* conf_module_config_search(char *name, void *pos);
int32_t conf_fini();

#endif
