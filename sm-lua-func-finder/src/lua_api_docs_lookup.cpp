#include "lua_api_docs.h"

#include <cstring>

const lua_api_doc_entry_t *find_lua_api_doc(
    bool is_userdata,
    const char *owner,
    const char *funcname)
{
  int want_kind = is_userdata ? 1 : 0;
  for ( size_t i = 0; i < g_lua_api_docs_count; ++i )
  {
    const lua_api_doc_entry_t &e = g_lua_api_docs[i];
    if ( e.owner_kind == want_kind
      && std::strcmp(e.owner, owner) == 0
      && std::strcmp(e.funcname, funcname) == 0 )
    {
      return &e;
    }
  }
  return nullptr;
}
