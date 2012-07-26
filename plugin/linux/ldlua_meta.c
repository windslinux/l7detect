#include <arpa/inet.h>
#include <stdlib.h>
#include "common.h"
#include "parser.h"
#include "ldlua.h"
#include "engine_comm.h"
#include "meta_buf.h"

LDLUA_METHOD meta_add_uint(lua_State* L);
LDLUA_METHOD meta_add_ff(lua_State* L);
LDLUA_METHOD meta_gc(lua_State *L);

LDLUA_CLASS_DEFINE(meta,FAIL_ON_NULL("LUA_META"),NOP);

extern uint32_t lde_engine_id;

static const luaL_reg meta_methods[] = {
	{"add_uint", meta_add_uint},
    {"add_ff", meta_add_ff},
    { NULL, NULL },
};

static const luaL_reg meta_meta[] = {
	{"__gc", meta_gc},
    { NULL, NULL },
};

meta* push_meta_to_stack(lua_State* L, meta s) {
    return push_meta(L, s);
}

LDLUA_METHOD meta_add_uint(lua_State* L)
{
	int32_t status;
#define LDLUA_OPTARG_META_TYPE 2
#define LDLUA_OPTARG_NUM 3
	meta ss = check_meta(L, 1);
    uint16_t type = (uint16_t)luaL_optlong(L, LDLUA_OPTARG_META_TYPE, 0);
	uint32_t num = (uint32_t)luaL_optlong(L, LDLUA_OPTARG_NUM, 0);

    status = meta_buffer_item_add(ss, type, &num, sizeof(uint32_t));
 	if (status != 0) {
		luaL_error(L,"savestr error, status %d\n", status);
	}
	return 0;
}

LDLUA_METHOD meta_add_ff(lua_State* L)
{
	int32_t status;
    meta_ff_t ff;
#define LDLUA_OPTARG_IP 2
#define LDLUA_OPTARG_PORT 3
#define LDLUA_OPTARG_APP_TYPE 4
	meta ss = check_meta(L, 1);
    ff.ip = (uint32_t)luaL_optlong(L, LDLUA_OPTARG_IP, 0);
	ff.port = (uint16_t)luaL_optlong(L, LDLUA_OPTARG_PORT, 0);
    ff.app_type = (uint32_t)luaL_optlong(L, LDLUA_OPTARG_APP_TYPE, 0);

    status = meta_buffer_item_add(ss, META_TYPE_FF, &ff, sizeof(ff));
 	if (status != 0) {
		luaL_error(L,"savestr error, status %d\n", status);
	}
	return 0;
}

LDLUA_METHOD meta_gc(lua_State *L)
{
	return 0;
}

int meta_register(lua_State* L)
{
	LDLUA_REGISTER_CLASS(meta);

    return 0;
}

