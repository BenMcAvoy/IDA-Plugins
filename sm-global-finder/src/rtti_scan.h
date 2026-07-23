#pragma once

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>

// One MSVC RTTI vtable ("??_7<ClassName>@@6B@") found in the database.
struct rtti_vtable_t
{
  qstring class_name;
  ea_t vft_ea = BADADDR;
};

enum class chain_status_t
{
  resolved,
  unresolved,
};

// Result of walking vft -> ctor -> allocator -> global for one class.
struct scan_result_t
{
  qstring class_name;
  ea_t vft_ea = BADADDR;
  ea_t ctor_ea = BADADDR;
  ea_t allocator_ea = BADADDR;
  ea_t global_ea = BADADDR;
  chain_status_t status = chain_status_t::unresolved;
  qstring reason; // populated when status == unresolved
};

// Enumerate every public name matching "??_7<ClassName>@@6B@".
qvector<rtti_vtable_t> find_rtti_vtables();

// Find every distinct function that writes vft_ea into an object (candidate
// constructors -- a class commonly has several: default/copy/move/etc, all
// stamping the same vtable pointer). Empty on failure, with *reason filled.
qvector<ea_t> find_ctor_candidates_for_vtable(ea_t vft_ea, qstring *reason);

// Find the candidate caller functions of ctor_ea (functions containing a call to it).
qvector<ea_t> find_callers_of(ea_t target_ea);
