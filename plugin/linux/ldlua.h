#ifndef __LDLUA_H__
#define __LDLUA_H__

#include "lua_ci.h"
#include "parser.h"
#include "plugin.h"
#include "meta_buf.h"

typedef packet_t* pkb;
typedef struct pkbrange_s* pkbrange;

typedef proto_comm_t* session;
typedef int gboolean;
typedef meta_hd_t* meta;

struct pkbrange_s {
	pkb pkt;
	int offset;
	int length;
};


void ldlua_register_classes(lua_State* L);
void ldlua_register_functions(lua_State* L);

#define PKB_LUA_INIT(L)		   \
	luaL_openlibs(L);		   \
	ldlua_register_classes(L); \
	ldlua_register_functions(L);

int pkb_register(lua_State* L);
int pkbrange_register(lua_State* L);
int session_register(lua_State* L);
int meta_register(lua_State* L);
pkb* push_pkb_to_stack(lua_State* L, pkb pkt);
session* push_session_to_stack(lua_State* L, session s);
meta* push_meta_to_stack(lua_State* L, meta s);

static inline uint32_t __app_length(pkb pkt)
{
	return pkt->real_applen;
}

static inline int __handle_offset(int offset, int length, uint32_t app_len)
{
	if (offset < 0) {
		offset = app_len + offset;
	}

	if ((offset < 0) || (length < 0) || (offset + length > (int)app_len)) {
        return -1;
	} else {
		return offset;
	}
}

#endif
