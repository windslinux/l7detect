#include <arpa/inet.h>
#include <stdlib.h>
#include "common.h"
#include "parser.h"
#include "ldlua.h"
#include "engine_comm.h"

LDLUA_METHOD session_savenum(lua_State* L);
LDLUA_METHOD session_savestr(lua_State* L);
LDLUA_METHOD session_saveindex(lua_State* L);
LDLUA_METHOD session_loadnum(lua_State* L);
LDLUA_METHOD session_loadstr(lua_State* L);
LDLUA_METHOD session_gc(lua_State *L);
LDLUA_METHOD session_state(lua_State *L);

LDLUA_CLASS_DEFINE(session,FAIL_ON_NULL("expired session"),NOP);

extern uint32_t lde_engine_id;/*现在和session相关的都是存放在lde的buffer里，需要改进*/

static const luaL_reg session_methods[] = {
	{"savenum", session_savenum},
	{"savestr", session_savestr},
	{"saveindex", session_saveindex},
	{"loadnum", session_loadnum},
	{"loadstr", session_loadstr},
	{"state", session_state},
    { NULL, NULL },
};

static const luaL_reg session_meta[] = {
	{"__gc", session_gc},
    { NULL, NULL },
};

session* push_session_to_stack(lua_State* L, session s) {
    return push_session(L, s);
}

LDLUA_METHOD session_savenum(lua_State* L)
{
	int32_t status;
#define LDLUA_OPTARG_NUM_INDEX 2
	session ss = check_session(L, 1);
	long num = luaL_optlong(L, LDLUA_OPTARG_NUM_INDEX, 0);

	status = protobuf_setbuf(ss->protobuf_head, lde_engine_id, sizeof(long), &num);
	if (status != 0) {
		luaL_error(L,"savenum error, status %d\n", status);
	}
	return 0;
}

LDLUA_METHOD session_savestr(lua_State* L)
{
	int32_t status;
#define LDLUA_OPTARG_STR_INDEX 2
	session ss = check_session(L, 1);
	char *str = (char *)luaL_optstring(L, LDLUA_OPTARG_STR_INDEX, 0);

	status = protobuf_setbuf(ss->protobuf_head, lde_engine_id, strlen(str), str);
	if (status != 0) {
		luaL_error(L,"savestr error, status %d\n", status);
	}
	return 0;
}

LDLUA_METHOD session_saveindex(lua_State* L)
{
#define LDLUA_OPTARG_SESSION_INDEX 2
#define LDLUA_OPTARG_SESSION_LEN 3
	session ss = check_session(L, 1);
	int index = luaL_optint(L, LDLUA_OPTARG_SESSION_INDEX, 0);
	int len = luaL_optint(L, LDLUA_OPTARG_SESSION_LEN, 0);
	packet_t *packet;
	int32_t status;
	uint32_t app_len = __app_length(ss->packet);
	lua_Integer n;

	index = __handle_offset(index, len, app_len);
	if (index < 0) {
		luaL_error(L,"Range is out of bounds\n");
		return 0;
	}

	packet = ss->packet;
	if ((index + len) >= (int)packet->real_applen) {
		luaL_error(L,"Range is out of bounds\n");
		return 0;
	}
	n = *(lua_Integer *)(packet->data + packet->app_offset + index);
	if (len <= 2) {
		n = ntohs(n);
	} else {
		n = ntohl(n);
	}
	status = protobuf_setbuf(ss->protobuf_head, lde_engine_id, sizeof(lua_Integer), &n);
	if (status != 0) {
		luaL_error(L,"session set error, status %d\n", status);
	}
	return 0;
}

LDLUA_METHOD session_state(lua_State* L)
{
	session ss = check_session(L, 1);
	lua_pushnumber(L, ss->state);
	return 1;
}

LDLUA_METHOD session_loadnum(lua_State* L)
{
	session ss = check_session(L, 1);

	protobuf_node_t *node = protobuf_find(ss->protobuf_head, lde_engine_id);
	if (node != NULL) {
		if (node->buf_data != NULL) {
			lua_Integer *n = (lua_Integer *)node->buf_data;
            lua_pushinteger(L, *n);
			return 1;
		} else {
			luaL_error(L,"session data not buffered");
		}
	} else {
		luaL_error(L,"node not found");
	}
	return 0;
}

LDLUA_METHOD session_loadstr(lua_State* L)
{
	session ss = check_session(L, 1);

	protobuf_node_t *node = protobuf_find(ss->protobuf_head, lde_engine_id);
	if (node != NULL) {
		if (node->buf_data != NULL) {
			char *n = (char *)node->buf_data;
			lua_pushstring(L, n);
			return 1;
		} else {
			luaL_error(L,"session data not buffered\n");
		}
	} else {
		luaL_error(L,"session not found\n");
	}
	return 0;
}

LDLUA_METHOD session_gc(lua_State *L)
{
	return 0;
}

int session_register(lua_State* L)
{
	LDLUA_REGISTER_CLASS(session);

    return 0;
}

