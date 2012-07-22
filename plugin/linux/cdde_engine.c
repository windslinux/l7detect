#include <string.h>
#include <assert.h>
#include "common.h"
#include "plugin.h"
#include "module_manage.h"
#include "log.h"
#include "helper.h"
#include "conf.h"
#include "parser.h"
#include "engine_comm.h"

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "ldlua.h"

static int32_t cdde_engine_init_global(module_info_t *this);
static int32_t cdde_engine_init_local(module_info_t *this, uint32_t thread_id);
static int32_t cdde_engine_process(module_info_t *this, void *data);
static int32_t cdde_engine_fini_global(module_info_t *this);
static int32_t cdde_engine_fini_local(module_info_t *this, uint32_t thread_id);
static log_t *pt_log;

static uint32_t cdde_engine_id;
int32_t lde_engine_id;/*lua session需要这个id，暂时再定义一次，需要修正*/

module_ops_t cdde_engine_ops = {
	.init_global = cdde_engine_init_global,
    .init_local = cdde_engine_init_local,
	.start = NULL,
	.process = cdde_engine_process,
	.result_get = NULL,
	.result_free = NULL,
	.fini_global = cdde_engine_fini_global,
    .fini_local = cdde_engine_fini_local,
};
typedef struct info_global {
    sf_proto_conf_t *conf;
} info_global_t;

typedef struct info_local {
	packet_t *packet;
    sf_proto_conf_t *conf;
	lua_State *lua_v;
	proto_comm_t *proto_comm;
} info_local_t;

static int32_t __cdde_conf_read(sf_proto_conf_t *conf, uint32_t cdde_engine_id)
{
	uint32_t i;
	for (i=0; i<conf->total_proto_num; i++) {
		uint32_t engine_mask = conf->protos[i].engine_mask;
		if ((engine_mask & (1<<cdde_engine_id)) == 0) {
			continue;
		}
	}
	return 0;
}

static int32_t cdde_match(void *data, uint32_t app_id)
{
	info_local_t *info;
	sf_proto_conf_t *conf;
	lua_State *L;
	packet_t *packet;
	int error, state;


	info = (info_local_t *)data;
	conf = info->conf;
	L = info->lua_v;
	packet = info->packet;

	lua_getglobal(L, conf->protos[app_id].name);
	lua_getfield(L, -1, "cdde");
	push_pkb_to_stack(L, packet);
	push_session_to_stack(L, info->proto_comm);
    push_meta_to_stack(L, packet->meta_hd);
	error = lua_pcall(L, 3, 1, 0);

	if (error) {
		log_error(pt_log, "%s\n", lua_tostring(L, -1));
		lua_pop(L, 1);
	} else {
		state = lua_tonumber(L, -1);
		lua_pop(L, 2);
		return state;
	}
	return 0;
}

static int32_t cdde_engine_init_global(module_info_t *this)
{
	sf_proto_conf_t *conf = (sf_proto_conf_t *)this->pub_rep;
	info_global_t *info;

    pt_log = conf->proto_log;
	info = zmalloc(info_global_t *, sizeof(info_global_t));
	assert(info);

	info->conf = conf;

	cdde_engine_id = engine_id_get(conf, "cdde");
	assert(cdde_engine_id != INVALID_ENGINE_ID);

    lde_engine_id = engine_id_get(conf, "lde");
	assert(lde_engine_id != INVALID_ENGINE_ID);

	__cdde_conf_read(conf, cdde_engine_id);
	this->pub_rep = (void *)info;
	return 0;
}

static int32_t cdde_engine_init_local(module_info_t *this, uint32_t thread_id)
{
    info_global_t *gp;
    info_local_t *lp;
    lua_State *L;
    sf_proto_conf_t *conf;
	int error;

    lp = zmalloc(info_local_t *, sizeof(info_local_t));
	assert(lp);

    gp = (info_global_t *)this->pub_rep;
    conf = gp->conf;
	L = luaL_newstate();
	assert(L);
	PKB_LUA_INIT(L);
    meta_register(L);
	luaL_loadbuffer(L, conf->app_luabuf, strlen(conf->app_luabuf), "cdde_engine");
	error = lua_pcall(L, 0, 0, 0);
	if (error) {
		err_print("%s\n", lua_tostring(L, -1));
		lua_pop(L, 1);
		return -1;
	}
	lua_settop(L, 0);
	lp->lua_v = L;
    lp->conf = conf;
    module_priv_rep_set(this, thread_id, (void *)lp);

    return 0;
}


static int32_t cdde_engine_process(module_info_t *this, void *data)
{
	proto_comm_t *proto_comm;
	packet_t *packet;
    info_global_t *gp;
	info_local_t *lp;
	sf_proto_conf_t *conf;
	uint32_t tag = 0;
	int32_t app_id;
	int32_t state = 0;

	proto_comm = (proto_comm_t *)data;
	packet = proto_comm->packet;
	gp = (info_global_t *)this->pub_rep;
	conf = gp->conf;
    app_id = proto_comm->app_id;

    lp = (info_local_t *)module_priv_rep_get(this, proto_comm->thread_id);
	lp->packet = packet;
	lp->proto_comm = proto_comm;
	longmask_all_clr(proto_comm->match_mask[cdde_engine_id]);
    longmask_bit_set(proto_comm->match_mask[cdde_engine_id], app_id);

	handle_engine_appid(conf, proto_comm->match_mask[cdde_engine_id],
                                 CS_ENG_TYPE, cdde_match, lp,
								 proto_comm->match_mask, cdde_engine_id, &tag, 1,
								 &state);

    proto_comm->state = state;
	return tag;
}

static int32_t cdde_engine_fini_local(module_info_t *this, uint32_t thread_id)
{
	info_local_t *info;

    info = (info_local_t *)module_priv_rep_get(this, thread_id);
	if (info->lua_v) {
		lua_close(info->lua_v);
	}
	free(info);
	return 0;
}
static int32_t cdde_engine_fini_global(module_info_t *this)
{
    info_global_t *info;

    info = (info_global_t *)this->pub_rep;
    free(info);
    return 0;
}
