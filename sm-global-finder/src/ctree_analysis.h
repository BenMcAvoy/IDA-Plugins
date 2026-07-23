#pragma once

#include <pro.h>
#include <ida.hpp>

// Decompile allocator_ea and look for the first assignment, occurring after the
// call to ctor_ea, of ctor_ea's return value into a fixed-address global
// (cot_obj lvalue) -- never a stack local, struct field, or array index.
//
// Returns the global's ea on success, or BADADDR with *reason filled on failure.
ea_t find_global_store(ea_t allocator_ea, ea_t ctor_ea, qstring *reason);

// Decompile ctor_ea itself and look for the first assignment, in program
// order, of ctor_ea's own "this" argument (its first argument lvar, per
// MSVC __fastcall/__thiscall convention) into a fixed-address global
// (cot_obj lvalue) -- i.e. "g_Foo = this;" written directly inside the
// constructor's own body, after stripping casts on the RHS.
//
// This covers the "constructor self-registration" idiom, which in practice
// is the dominant singleton shape in this binary: the ctor itself stashes
// `this` into a global, rather than some caller storing the ctor's return
// value (that shape is what find_global_store() above looks for instead).
//
// Returns the global's ea on success, or BADADDR with *reason filled on failure
// (no containing function, decompilation failure, no argument lvars found, or
// no matching self-store located anywhere in the ctor's body).
ea_t find_self_registered_global(ea_t ctor_ea, qstring *reason);
