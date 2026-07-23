#pragma once

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>

// Result of attempting to synthesize a best-effort struct layout for one
// class from its constructor's direct field-initialization writes on
// "this". This is a conservative, read-only-application v1: on success it
// only registers a new Local Type and leaves a comment on the constructor
// pointing at it -- it never retypes any lvar/parameter/global (see
// struct_synth.cpp for the full rationale).
struct layout_synth_result_t
{
  qstring class_name;
  ea_t ctor_ea = BADADDR;
  qstring type_name;  // Local Types name, populated when resolved == true
  bool resolved = false;
  qstring reason;     // populated when resolved == false
};

// Decompiles ctor_ea and walks its body for "*(TYPE*)(this + N) = expr;"
// (including the bare "*(TYPE*)this = expr;" shape Hex-Rays uses for offset
// 0, with no explicit "+ 0" node -- verified against a real ctor) /
// already-member-accessed "this->field = expr;" style writes on the
// constructor's own "this" parameter (its first is_arg_var() lvar), and --
// provided the recorded field writes don't conflict with each other --
// synthesizes a best-effort struct type describing the class's memory
// layout. The type is registered into Local Types (via
// tinfo_t::set_named_type) under a "__sm_layout_<ClassName>" name (any
// "::" in class_name replaced with "_"), and a comment is left on the
// constructor pointing at it.
//
// is_polymorphic should be true whenever vft_ea denotes a real RTTI vtable
// resolved for this class -- this plugin only ever calls this function for
// such classes (every caller loops over find_rtti_vtables() results), but
// the flag is threaded through explicitly rather than assumed, both for
// clarity at the call site and so this function stays reusable if a future
// caller ever wants to try it against a non-RTTI class. When true and
// offset 0 isn't otherwise covered by a recorded field write, an explicit
// "vfptr" (void *) member is inserted at offset 0 -- a known fact, not a
// guess, since find_rtti_vtables() already proved a vtable pointer lives
// there.
layout_synth_result_t synthesize_struct_layout(
    ea_t ctor_ea,
    const qstring &class_name,
    ea_t vft_ea,
    bool is_polymorphic);
