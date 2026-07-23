#pragma once

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>

// One base class contribution to a derived class's hierarchy, resolved from
// the base-class array of a _RTTIClassHierarchyDescriptor (index 1..N-1;
// index 0, the class itself, is excluded before this struct is populated).
struct base_class_info_t
{
  qstring class_name;
  int32 mdisp = 0;      // byte displacement of this base within the derived object
  bool is_virtual = false;
};

// Result of walking the MSVC RTTI Complete Object Locator chain for one
// vtable: COL -> _RTTIClassHierarchyDescriptor -> base-class array ->
// _RTTIBaseClassDescriptor[] -> _TypeDescriptor names.
struct hierarchy_info_t
{
  qstring class_name;
  ea_t vft_ea = BADADDR;
  qvector<base_class_info_t> bases; // direct + indirect bases, self excluded
  bool is_multiple_inheritance = false;
};

// Walks the MSVC x64 RTTI structures rooted at the _RTTICompleteObjectLocator
// pointer stored at vft_ea - 8 (see rtti_hierarchy.cpp for the full layout
// this mirrors) and fills *out with the resolved class hierarchy.
//
// Returns false (and fills *reason) if the COL pointer, class hierarchy
// descriptor, base-class array, or any base-class descriptor cannot be read
// or looks unreasonable (e.g. an out-of-range base-class count).
bool resolve_class_hierarchy(ea_t vft_ea, hierarchy_info_t *out, qstring *reason);
