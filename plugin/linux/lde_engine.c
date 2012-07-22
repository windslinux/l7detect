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

static int32_t lde_engine_init_global(module_info_t *this);
static int32_t lde_engine_init_local(module_info_t *this, uint32_t thread_id);
static int32_t lde_engine_process(module_info_t *this, void *data);
static int32_t lde_engine_fini_global(module_info_t *this);
static int32_t lde_engine_fini_local(module_info_t *this, uint32_t thread_id);
static log_t *pt_log;

uint32_t lde_engine_id;

module_ops_t lde_engine_ops = {
	.init_global = lde_engine_init_global,
    .init_local = lde_engine_init_local,
	.start = NULL,
	.process = lde_engine_process,
	.result_get = NULL,
	.result_free = NULL,
	.fini_global = lde_engine_fini_global,
    .fini_local = lde_engine_fini_local,
};
typedef struct info_global {
    sf_proto_conf_t *conf;
	longmask_t *lde_pre;/*前面有别的引擎的掩码*/
	longmask_t *lde_cur;/*lde引擎开始的掩码，为了提高效率和上面的mask分开*/
} info_global_t;

typedef struct info_local {
	packet_t *packet;
    sf_proto_conf_t *conf;
	lua_State *lua_v;
	proto_comm_t *proto_comm;
} info_local_t;

static int32_t __lde_conf_read(sf_proto_conf_t *conf, uint32_t lde_engine_id,
							   longmask_t *lde_pre, longmask_t *lde_cur)
{
	uint32_t i;
	for (i=0; i<conf->total_proto_num; i++) {
		uint32_t engine_mask = conf->protos[i].engine_mask;
		if ((engine_mask & (1<<lde_engine_id)) == 0) {
			continue;
		}
		if ((engine_mask & ~((0xffffffff) << lde_engine_id)) != 0) {
			/*lde前面还有别的引擎*/
			longmask_bit_set(lde_pre, i);
		} else {
			longmask_bit_set(lde_cur, i);
		}
	}
	return 0;
}

static int32_t lde_match(void *data, uint32_t app_id)
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
	lua_getfield(L, -1, "lde");
	push_pkb_to_stack(L, packet);
	push_session_to_stack(L, info->proto_comm);
	error = lua_pcall(L, 2, 1, 0);

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

static int32_t lde_engine_init_global(module_info_t *this)
{
	sf_proto_conf_t *conf = (sf_proto_conf_t *)this->pub_rep;
	info_global_t *info;

    pt_log = conf->proto_log;
	info = zmalloc(info_global_t *, sizeof(info_global_t));
	assert(info);

	info->lde_pre = longmask_create(conf->total_proto_num);
	assert(info->lde_pre);

	info->lde_cur = longmask_create(conf->total_proto_num);
	assert(info->lde_cur);
	info->conf = conf;

	lde_engine_id = engine_id_get(conf, "lde");
	assert(lde_engine_id != INVALID_ENGINE_ID);

	__lde_conf_read(conf, lde_engine_id, info->lde_pre, info->lde_cur);
	this->pub_rep = (void *)info;
	return 0;
}

static int32_t lde_engine_init_local(module_info_t *this, uint32_t thread_id)
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
	luaL_loadbuffer(L, conf->app_luabuf, strlen(conf->app_luabuf), "lde_engine");
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


static int32_t lde_engine_process(module_info_t *this, void *data)
{
	proto_comm_t *proto_comm;
	packet_t *packet;
    info_global_t *gp;
	info_local_t *lp;
	sf_proto_conf_t *conf;
	longmask_t *mask;
	uint32_t tag = 0;
	int32_t app_id, status;
	int32_t state = 0;

	proto_comm = (proto_comm_t *)data;
	packet = proto_comm->packet;
	gp = (info_global_t *)this->pub_rep;
	conf = gp->conf;

    lp = (info_local_t *)module_priv_rep_get(this, proto_comm->thread_id);
	lp->packet = packet;
	lp->proto_comm = proto_comm;
	mask = proto_comm->match_mask[lde_engine_id];
	app_id = handle_engine_appid(conf, proto_comm->match_mask[lde_engine_id],
                                 CS_ENG_TYPE, lde_match, lp,
								 proto_comm->match_mask, lde_engine_id, &tag, 1,
								 &state);

	longmask_all_clr(proto_comm->match_mask[lde_engine_id]);
	if (app_id < 0) {
		mask = gp->lde_cur;
		app_id = handle_engine_appid(conf, gp->lde_cur,
									 CS_ENG_TYPE, lde_match,  lp,
									 proto_comm->match_mask, lde_engine_id, &tag, 0,
									 &state);

	}
	if (app_id >= 0) {
		proto_comm->app_id = app_id;
		proto_comm->state = state;

		if (state != (int32_t)conf->final_state) {
			status = protobuf_setmask(proto_comm->protobuf_head, lde_engine_id, app_id, mask);

			if (status != 0) {
				log_error(pt_log, "protobuf setmask error, status %d\n", status);
				return 0;
			}
		}
	} else {
		proto_comm->app_id = INVALID_PROTO_ID;
	}
	return tag;
}

static int32_t lde_engine_fini_local(module_info_t *this, uint32_t thread_id)
{
	info_local_t *info;

    info = (info_local_t *)module_priv_rep_get(this, thread_id);
	if (info->lua_v) {
		lua_close(info->lua_v);
	}
	free(info);
	return 0;
}
static int32_t lde_engine_fini_global(module_info_t *this)
{
    info_global_t *info;

    info = (info_global_t *)this->pub_rep;
    if (info->lde_pre) {
		longmask_destroy(info->lde_pre);
	}

	if (info->lde_cur) {
		longmask_destroy(info->lde_cur);
	}
    return 0;
}
