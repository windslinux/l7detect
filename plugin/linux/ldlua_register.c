#include "ldlua.h"
void ldlua_register_classes(lua_State* L)
{
	pkb_register(L);
	pkbrange_register(L);
	session_register(L);
}
void ldlua_register_functions(lua_State* L)
{

}
