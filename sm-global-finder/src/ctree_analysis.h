#pragma once

#include <pro.h>
#include <ida.hpp>

// Decompile allocator_ea and look for the first assignment, occurring after the
// call to ctor_ea, of ctor_ea's return value into a fixed-address global
// (cot_obj lvalue) -- never a stack local, struct field, or array index.
//
// Returns the global's ea on success, or BADADDR with *reason filled on failure.
ea_t find_global_store(ea_t allocator_ea, ea_t ctor_ea, qstring *reason);
