#include "rtti_scan.h"
#include "ctree_analysis.h"

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <name.hpp>
#include <funcs.hpp>
#include <hexrays.hpp>
#include <fpro.h>

namespace
{

// -------------------------------------------------------------------------
// Results chooser
// -------------------------------------------------------------------------

struct scan_results_popup_t final : chooser_t
{
  static const int widths[];
  static const char *const headers[];

  const qvector<scan_result_t> &results;

  explicit scan_results_popup_t(const qvector<scan_result_t> &results_)
    : chooser_t(
        CH_MODAL | CH_KEEP,
        6,
        widths,
        headers,
        "SM Global Finder Results"),
      results(results_)
  {
  }

  size_t idaapi get_count() const override
  {
    return results.size();
  }

  ea_t idaapi get_ea(size_t n) const override
  {
    const scan_result_t &r = results[n];
    return r.status == chain_status_t::resolved ? r.allocator_ea : r.vft_ea;
  }

  void idaapi get_row(
        qstrvec_t *cols_,
        int *,
        chooser_item_attrs_t *,
        size_t n) const override
  {
    const scan_result_t &r = results[n];
    qstrvec_t &cols = *cols_;
    cols[0] = r.class_name;
    cols[1].sprnt("%a", r.vft_ea);
    if ( r.status == chain_status_t::resolved )
    {
      cols[2].sprnt("%a", r.ctor_ea);
      cols[3].sprnt("%a", r.allocator_ea);
      cols[4].sprnt("%a", r.global_ea);
      cols[5] = "resolved";
    }
    else
    {
      if ( r.ctor_ea == BADADDR )
        cols[2] = "-";
      else
        cols[2].sprnt("%a", r.ctor_ea);
      cols[3] = "-";
      cols[4] = "-";
      cols[5].sprnt("unresolved: %s", r.reason.c_str());
    }
  }
};

const int scan_results_popup_t::widths[] =
{
  24,
  CHCOL_HEX | 16,
  CHCOL_HEX | 16,
  CHCOL_HEX | 16,
  CHCOL_HEX | 16,
  50,
};

const char *const scan_results_popup_t::headers[] =
{
  "Class",
  "VTable",
  "Constructor",
  "Allocator",
  "Global",
  "Status",
};

// -------------------------------------------------------------------------
// Scan pipeline: vft -> ctor -> allocator -> global, with bounded hop search.
// -------------------------------------------------------------------------

constexpr int MAX_ALLOCATOR_HOPS = 2;

// Tries to resolve the allocator+global for one specific ctor candidate,
// searching up to MAX_ALLOCATOR_HOPS levels of callers.
bool resolve_allocator_chain(ea_t ctor_ea, scan_result_t *result, qstring *out_reason)
{
  qvector<ea_t> frontier = find_callers_of(ctor_ea);
  if ( frontier.empty() )
  {
    *out_reason = "constructor has no call xrefs";
    return false;
  }

  qstring last_reason = "no global store found within max call hops";
  for ( int depth = 0; depth < MAX_ALLOCATOR_HOPS && !frontier.empty(); ++depth )
  {
    qvector<ea_t> next_frontier;
    for ( ea_t candidate : frontier )
    {
      qstring why;
      ea_t global_ea = find_global_store(candidate, ctor_ea, &why);
      if ( global_ea != BADADDR )
      {
        result->ctor_ea = ctor_ea;
        result->allocator_ea = candidate;
        result->global_ea = global_ea;
        result->status = chain_status_t::resolved;
        return true;
      }
      last_reason = why;

      for ( ea_t caller : find_callers_of(candidate) )
        next_frontier.push_back(caller);
    }
    frontier.swap(next_frontier);
  }

  *out_reason = last_reason;
  return false;
}

scan_result_t analyze_class(const rtti_vtable_t &vt)
{
  scan_result_t result;
  result.class_name = vt.class_name;
  result.vft_ea = vt.vft_ea;

  qstring reason;
  qvector<ea_t> ctor_candidates = find_ctor_candidates_for_vtable(vt.vft_ea, &reason);
  if ( ctor_candidates.empty() )
  {
    result.reason = reason;
    return result;
  }

  // A class commonly has several constructors (default/copy/move/...) that
  // all stamp the same vtable pointer -- try each until one leads to a
  // resolvable allocator+global chain.
  qstring last_reason;
  for ( ea_t ctor_ea : ctor_candidates )
  {
    qstring why;
    if ( resolve_allocator_chain(ctor_ea, &result, &why) )
      return result;
    last_reason = why;
  }

  result.ctor_ea = ctor_candidates[0];
  result.reason.sprnt(
      "%s (tried %d ctor candidate%s)",
      last_reason.c_str(),
      int(ctor_candidates.size()),
      ctor_candidates.size() == 1 ? "" : "s");
  return result;
}

void apply_result(const scan_result_t &r)
{
  if ( r.status != chain_status_t::resolved )
    return;

  qstring ctor_name;
  ctor_name.sprnt("%s::ctor", r.class_name.c_str());
  set_name(r.ctor_ea, ctor_name.c_str(), SN_FORCE | SN_NOWARN);

  qstring alloc_name;
  alloc_name.sprnt("%s::getInstance", r.class_name.c_str());
  set_name(r.allocator_ea, alloc_name.c_str(), SN_FORCE | SN_NOWARN);

  qstring global_name;
  global_name.sprnt("g_%s", r.class_name.c_str());
  set_name(r.global_ea, global_name.c_str(), SN_FORCE | SN_NOWARN);

  qstring cmt;
  cmt.sprnt(
      "Singleton pattern: constructs %s, global at %s (%a)",
      r.class_name.c_str(),
      global_name.c_str(),
      r.global_ea);

  func_t *ctor_fn = get_func(r.ctor_ea);
  if ( ctor_fn != nullptr )
    set_func_cmt(ctor_fn, cmt.c_str(), true);

  func_t *alloc_fn = get_func(r.allocator_ea);
  if ( alloc_fn != nullptr )
    set_func_cmt(alloc_fn, cmt.c_str(), true);
}

// Writes one line per scanned class to a log file next to the current
// database, so results survive after the modal chooser is closed.
qstring write_scan_log(const qvector<scan_result_t> &results)
{
  char dir[QMAXPATH];
  qdirname(dir, sizeof(dir), get_path(PATH_TYPE_IDB));

  qstring log_path;
  log_path.sprnt("%s/sm_global_finder_scan.log", dir);

  FILE *fp = qfopen(log_path.c_str(), "w");
  if ( fp == nullptr )
    return qstring();

  for ( const scan_result_t &r : results )
  {
    if ( r.status == chain_status_t::resolved )
    {
      qfprintf(
          fp,
          "RESOLVED   %-40s vft=%a ctor=%a allocator=%a global=%a\n",
          r.class_name.c_str(),
          r.vft_ea,
          r.ctor_ea,
          r.allocator_ea,
          r.global_ea);
    }
    else
    {
      qfprintf(
          fp,
          "UNRESOLVED %-40s vft=%a reason=%s\n",
          r.class_name.c_str(),
          r.vft_ea,
          r.reason.c_str());
    }
  }

  qfclose(fp);
  return log_path;
}

bool idaapi run(size_t)
{
  qvector<rtti_vtable_t> vtables = find_rtti_vtables();
  if ( vtables.empty() )
  {
    warning("SM Global Finder: no MSVC RTTI vtables (??_7...@@6B@) found in this database.");
    return true;
  }

  qvector<scan_result_t> results;
  results.reserve(vtables.size());
  size_t resolved_count = 0;
  for ( const rtti_vtable_t &vt : vtables )
  {
    scan_result_t r = analyze_class(vt);
    if ( r.status == chain_status_t::resolved )
    {
      apply_result(r);
      ++resolved_count;
    }
    results.push_back(r);
  }

  qstring log_path = write_scan_log(results);

  msg(
      "SM Global Finder: scanned %d classes, resolved %d, unresolved %d. Log: %s\n",
      int(results.size()),
      int(resolved_count),
      int(results.size() - resolved_count),
      log_path.empty() ? "<failed to write>" : log_path.c_str());

  scan_results_popup_t popup(results);
  popup.choose();
  return true;
}

plugmod_t *idaapi init()
{
  if ( !init_hexrays_plugin() )
    return nullptr;
  return PLUGIN_OK;
}

} // namespace

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,
  init,
  nullptr,
  run,
  "Scans MSVC RTTI vtables for the vft->ctor->allocator->global singleton pattern and renames the discovered chain.",
  "",
  "SM Global Finder",
  ""
};
