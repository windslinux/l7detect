#include <string.h>
#include <assert.h>

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

static int32_t __parse_sde_proto_conf(proto_conf_t *proto_conf,
									  uint32_t app_id, uint32_t engine_id)
{
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
		if (__parse_sde_proto_conf(&conf->protos[i], i, sde_engine_id) != 0) {
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

