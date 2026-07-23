#pragma once

#include <cstddef>

// One documented function pulled from the sm_api_differ json_ch1 dump
// (see gen_api_docs.py). owner_kind distinguishes a dotted static namespace
// ("sm.audio") from a userdata type name ("Character").
struct lua_api_doc_entry_t
{
  int owner_kind;        // 0 = namespace, 1 = userdata
  const char *owner;
  const char *funcname;
  const char *params;    // "type name, type name, ..." (already formatted)
  const char *summary;    // first non-@tag doc line
};

extern const lua_api_doc_entry_t g_lua_api_docs[];
extern const size_t g_lua_api_docs_count;

// Finds the doc entry for (is_userdata, owner, funcname), or nullptr if the
// sm_api_differ dump doesn't cover it (e.g. it wasn't documented yet).
const lua_api_doc_entry_t *find_lua_api_doc(
    bool is_userdata,
    const char *owner,
    const char *funcname);
