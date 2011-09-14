#ifndef __LDLUA_H__
#define __LDLUA_H__

#include "lua_ci.h"
#include "parser.h"

typedef packet_t * pkb;
typedef struct pkbrange_s * pkbrange;
typedef int gboolean;

struct pkbrange_s {
	pkb pkt;
	int offset;
	int length;
};


void ldlua_register_classes(lua_State* L);
void ldlua_register_functions(lua_State* L);

#define LDLUA_INIT(L)		   \
	luaL_openlibs(L);		   \
	ldlua_register_classes(L); \
	ldlua_register_functions(L);

int pkb_register(lua_State* L);
int pkbrange_register(lua_State* L);
pkb* push_pkb_to_stack(lua_State* L, pkb pkt);
#endif