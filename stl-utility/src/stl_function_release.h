#pragma once

#include <hexrays.hpp>

namespace stl_utility
{

// Recognizes the inlined MSVC std::_Func_impl_no_alloc<Callable,...> teardown
// sequence -- the internal type behind std::function/delegate-style callback
// storage. A std::function is constructed on the stack (self-pointer "v13" =
// "v12", the SBO-indicator tracking pointer), passed by pointer to some
// registration/dispatch call, then torn down inline with this exact shape:
//
//   if ( v13 )
//   {
//     v7 = v12;                    // copy of the base/storage pointer
//     LOBYTE(v7) = v13 != v12;     // "is heap-allocated" flag, repurposing v7's low byte
//     v13->VTABLE[0x4](v7);        // std::_Func_class::_Delete_this(bool), through the object's own vtable
//     v13 = nullptr;
//   }
//
// This is pure ABI boilerplate emitted at every inlined std::function scope
// exit -- not useful to a reverse engineer -- so it's collapsed into a
// single `~function(v13);`-shaped synthetic call, mirroring
// stl_shared_ptr_release.cpp's approach for shared_ptr/weak_ptr release.
// Runs at hxe_maturity/CMAT_FINAL, mutating the ctree via
// cinsn_t::replace_by before pseudocode text is generated.
//
// The flag-computation setup statement(s) ("v7 = v12", "LOBYTE(v7) = ...")
// are decompiler-representation-sensitive and are NOT required by the
// matcher; the strict, distinctive backstop is the bare-pointer `if`
// condition plus an indirect/computed call somewhere in the block followed
// later by the tracking pointer being nulled out -- mirroring how the
// string-release matcher leans on a distinctive member-access shape rather
// than validating callee/vtable-slot names precisely.
//
// Returns the number of collapsed occurrences within `cfunc`'s body.
int collapse_function_releases(cfunc_t *cfunc);

} // namespace stl_utility
