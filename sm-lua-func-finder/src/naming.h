#pragma once

#include <pro.h>
#include <ida.hpp>

#include "reg_scan.h"

// A single (owner, funcname) label contributing to a renamed function --
// one function can carry several when the same implementation is shared
// across owners (e.g. a common helper registered under two userdata types).
struct name_label_t
{
  qstring owner;
  bool is_userdata;
  qstring funcname;
};

struct final_name_t
{
  ea_t func_ea;
  qstring name;         // e.g. "Lua_sm_audio_play" or "Lua_Tool_Character_getTpBonePos"
  qstring comment;      // doc summary pulled from lua_api_docs.gen.cpp, if any matched
  qvector<name_label_t> labels;
};

// Groups scan results by func_ea, merges duplicate (owner, funcname) pairs,
// and builds the final IDA name + comment for each distinct function.
qvector<final_name_t> build_final_names(const qvector<lua_func_reg_t> &regs);
