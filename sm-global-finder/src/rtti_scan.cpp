#include "rtti_scan.h"

#include <name.hpp>
#include <demangle.hpp>
#include <xref.hpp>
#include <funcs.hpp>

#include <qset.hpp>

#include <cstring>

namespace
{

bool has_rtti_vtable_shape(const char *name)
{
  // Matches "??_7<ClassName>@@6B@"
  if ( qstrncmp(name, "??_7", 4) != 0 )
    return false;
  size_t len = qstrlen(name);
  static const char suffix[] = "@@6B@";
  size_t suffix_len = sizeof(suffix) - 1;
  if ( len <= 4 + suffix_len )
    return false;
  return qstrcmp(name + len - suffix_len, suffix) == 0;
}

// std:: (and other STL/CRT) types and class templates are never the kind of
// hand-written singleton this plugin looks for -- skip them so the scan
// doesn't waste time decompiling them and doesn't produce garbage class
// names out of deeply nested template argument lists.
bool is_noise_vtable(const char *mangled_name)
{
  return strstr(mangled_name, "?$") != nullptr    // class template instantiation
      || strstr(mangled_name, "@std@@") != nullptr; // std:: namespace
}

// Extract "<ClassName>" out of a demangled "const ClassName::`vftable'" string,
// falling back to a manual strip of the mangled name if demangling fails.
qstring extract_class_name(const char *mangled)
{
  qstring demangled;
  int32 code = demangle_name(&demangled, mangled, MNG_SHORT_FORM);
  if ( code >= 0 )
  {
    // Typical shapes: "ClassName::`vftable'" or "const ClassName::`vftable'"
    size_t pos = demangled.find("::`vftable'");
    if ( pos != qstring::npos )
    {
      qstring cls = demangled.substr(0, pos);
      size_t space = cls.rfind(' ');
      if ( space != qstring::npos )
        // NOTE: qstring::substr(pos, n) takes an *ending index*, not a
        // length (unlike std::string::substr) -- so the end argument here
        // must be cls.length(), not a remaining-character count.
        cls = cls.substr(space + 1, cls.length());
      if ( !cls.empty() )
        return cls;
    }
  }

  // Fallback: strip "??_7" prefix and "@@6B@" suffix directly from the mangled name.
  qstring raw = mangled;
  // See note above: qstring::substr's 2nd arg is an ending index, so pass
  // raw.length() (the full end), not raw.length()-4.
  raw = raw.substr(4, raw.length());
  size_t suffix_pos = raw.find("@@6B@");
  if ( suffix_pos != qstring::npos )
    raw = raw.substr(0, suffix_pos);
  return raw;
}

} // namespace

qvector<rtti_vtable_t> find_rtti_vtables()
{
  qvector<rtti_vtable_t> out;
  size_t cnt = get_nlist_size();
  for ( size_t i = 0; i < cnt; ++i )
  {
    const char *name = get_nlist_name(i);
    if ( name == nullptr || !has_rtti_vtable_shape(name) || is_noise_vtable(name) )
      continue;

    rtti_vtable_t entry;
    entry.vft_ea = get_nlist_ea(i);
    entry.class_name = extract_class_name(name);
    if ( entry.vft_ea != BADADDR && !entry.class_name.empty() )
      out.push_back(entry);
  }
  return out;
}

qvector<ea_t> find_ctor_candidates_for_vtable(ea_t vft_ea, qstring *reason)
{
  qvector<ea_t> candidates;
  qset<ea_t> seen;
  xrefblk_t xb;
  for ( bool ok = xb.first_to(vft_ea, XREF_DATA); ok; ok = xb.next_to() )
  {
    func_t *pfn = get_func(xb.from);
    if ( pfn == nullptr )
      continue;
    ea_t start = pfn->start_ea;
    if ( seen.find(start) == seen.end() )
    {
      seen.insert(start);
      candidates.push_back(start);
    }
  }

  if ( candidates.empty() && reason != nullptr )
    *reason = "no data xrefs to vtable resolve to a containing function";

  return candidates;
}

qvector<ea_t> find_callers_of(ea_t target_ea)
{
  qvector<ea_t> out;
  qset<ea_t> seen;
  xrefblk_t xb;
  for ( bool ok = xb.first_to(target_ea, XREF_ALL); ok; ok = xb.next_to() )
  {
    if ( xb.type != fl_CN && xb.type != fl_CF )
      continue;
    func_t *pfn = get_func(xb.from);
    if ( pfn == nullptr )
      continue;
    ea_t start = pfn->start_ea;
    if ( seen.find(start) == seen.end() )
    {
      seen.insert(start);
      out.push_back(start);
    }
  }
  return out;
}
