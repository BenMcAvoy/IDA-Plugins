#include "rtti_scan.h"
#include "rtti_hierarchy.h"
#include "ctree_analysis.h"
#include "struct_synth.h"

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <name.hpp>
#include <funcs.hpp>
#include <hexrays.hpp>
#include <fpro.h>
#include <bytes.hpp>

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

// Tries the "constructor self-registration" shape first: the ctor itself
// stores its own "this" argument into a global (verified against the real
// binary to be the dominant singleton idiom here -- see ctree_analysis.h).
// If the ctor's body has such a store, we still need something to rename
// as "ClassName::create"; the most useful candidate is a real caller
// of the ctor (the allocator wrapper that does `operator new` + call ctor,
// unconditionally, with no check of whether the global is already set --
// so it is a plain factory, not a lazy singleton accessor).
// If the ctor has no callers at all, there is nothing sane to rename as the
// allocator distinct from the ctor itself, so this path reports failure and
// lets the caller fall back to resolve_allocator_chain() instead of aliasing
// create onto the same address as the ctor (which would just clobber
// the ctor's own rename).
bool resolve_self_registration(ea_t ctor_ea, scan_result_t *result, qstring *out_reason)
{
  qstring why;
  ea_t global_ea = find_self_registered_global(ctor_ea, &why);
  if ( global_ea == BADADDR )
  {
    *out_reason = why;
    return false;
  }

  qvector<ea_t> callers = find_callers_of(ctor_ea);
  if ( callers.empty() )
  {
    *out_reason = "self-registration found a global store but constructor has no call xrefs to name as an allocator";
    return false;
  }

  result->ctor_ea = ctor_ea;
  result->allocator_ea = callers[0];
  result->global_ea = global_ea;
  result->status = chain_status_t::resolved;
  return true;
}

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
    // Self-registration (ctor stores its own "this" into a global) is the
    // dominant real-world shape in this binary -- try it before the
    // caller-search chain below.
    qstring self_why;
    if ( resolve_self_registration(ctor_ea, &result, &self_why) )
      return result;

    qstring chain_why;
    if ( resolve_allocator_chain(ctor_ea, &result, &chain_why) )
      return result;

    last_reason.sprnt(
        "self-registration: %s; caller-search: %s",
        self_why.c_str(),
        chain_why.c_str());
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
  alloc_name.sprnt("%s::create", r.class_name.c_str());
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

// -------------------------------------------------------------------------
// RTTI class hierarchy enrichment: independent of the singleton chain scan
// above -- walks the real MSVC RTTI structures (Complete Object Locator ->
// Class Hierarchy Descriptor -> base-class array) for each vtable already
// found by find_rtti_vtables() and leaves a descriptive comment at the
// vtable's address.
// -------------------------------------------------------------------------

qstring build_hierarchy_comment(const hierarchy_info_t &h)
{
  qstring cmt;
  cmt.sprnt("RTTI hierarchy: %s :", h.class_name.c_str());

  bool show_offsets = h.bases.size() > 1 || h.is_multiple_inheritance;
  for ( size_t i = 0; i < h.bases.size(); ++i )
  {
    const base_class_info_t &b = h.bases[i];
    if ( i > 0 )
      cmt += ",";
    cmt += " ";
    cmt += b.class_name;
    if ( show_offsets )
    {
      qstring off;
      off.sprnt(" (+0x%x)", b.mdisp);
      cmt += off;
    }
    if ( b.is_virtual )
      cmt += " [virtual]";
  }

  if ( h.is_multiple_inheritance )
    cmt += "   [multiple inheritance]";

  return cmt;
}

void apply_hierarchy_comment(const hierarchy_info_t &h)
{
  qstring cmt = build_hierarchy_comment(h);
  set_cmt(h.vft_ea, cmt.c_str(), false);
}

// -------------------------------------------------------------------------
// Constructor-driven struct layout synthesis: also independent of the
// singleton chain scan above -- decompiles each class's ctor candidate
// (whichever one the singleton-chain scan above already settled on, so we
// don't re-derive/re-guess which candidate to use) and, on success, leaves
// a comment on the constructor pointing at the synthesized Local Type. See
// struct_synth.h/.cpp for why this never auto-applies the type anywhere.
// -------------------------------------------------------------------------

void apply_layout_result(const layout_synth_result_t &l)
{
  qstring cmt;
  cmt.sprnt(
      "Struct layout guess synthesized from this constructor's field writes -- "
      "see Local Type '%s' (not auto-applied; review and apply manually).",
      l.type_name.c_str());

  func_t *ctor_fn = get_func(l.ctor_ea);
  if ( ctor_fn != nullptr )
    set_func_cmt(ctor_fn, cmt.c_str(), true);
}

// Writes one line per scanned class to a log file next to the current
// database, so results survive after the modal chooser is closed.
qstring write_scan_log(
    const qvector<scan_result_t> &results,
    const qvector<hierarchy_info_t> &hierarchies,
    const qvector<rtti_vtable_t> &unresolved_hierarchy_vtables,
    const qvector<layout_synth_result_t> &layouts)
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

  qfprintf(fp, "\n--- RTTI class hierarchy resolution ---\n");
  for ( const hierarchy_info_t &h : hierarchies )
  {
    qfprintf(
        fp,
        "HIERARCHY  %-40s vft=%a %s\n",
        h.class_name.c_str(),
        h.vft_ea,
        build_hierarchy_comment(h).c_str());
  }
  for ( const rtti_vtable_t &vt : unresolved_hierarchy_vtables )
  {
    qfprintf(
        fp,
        "HIERARCHY  %-40s vft=%a unresolved\n",
        vt.class_name.c_str(),
        vt.vft_ea);
  }

  qfprintf(fp, "\n--- Struct layout synthesis ---\n");
  for ( const layout_synth_result_t &l : layouts )
  {
    if ( l.resolved )
    {
      qfprintf(
          fp,
          "LAYOUT     %-40s ctor=%a type=%s\n",
          l.class_name.c_str(),
          l.ctor_ea,
          l.type_name.c_str());
    }
    else
    {
      qfprintf(
          fp,
          "LAYOUT     %-40s ctor=%a reason=%s\n",
          l.class_name.c_str(),
          l.ctor_ea,
          l.reason.c_str());
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

  qvector<hierarchy_info_t> hierarchies;
  qvector<rtti_vtable_t> unresolved_hierarchy_vtables;
  size_t hierarchy_resolved_count = 0;

  qvector<layout_synth_result_t> layouts;
  size_t layout_resolved_count = 0;

  for ( const rtti_vtable_t &vt : vtables )
  {
    scan_result_t r = analyze_class(vt);
    if ( r.status == chain_status_t::resolved )
    {
      apply_result(r);
      ++resolved_count;
    }
    results.push_back(r);

    // Independent RTTI hierarchy enrichment -- runs for every discovered
    // vtable regardless of whether the singleton chain above resolved.
    hierarchy_info_t hinfo;
    qstring hreason;
    if ( resolve_class_hierarchy(vt.vft_ea, &hinfo, &hreason) )
    {
      apply_hierarchy_comment(hinfo);
      hierarchies.push_back(hinfo);
      ++hierarchy_resolved_count;
    }
    else
    {
      unresolved_hierarchy_vtables.push_back(vt);
    }

    // Independent struct layout synthesis -- reuses whichever ctor
    // candidate the singleton-chain scan above already settled on (r.ctor_ea
    // is only BADADDR when find_ctor_candidates_for_vtable() found nothing
    // at all, in which case there's no ctor to decompile here either).
    if ( r.ctor_ea != BADADDR )
    {
      layout_synth_result_t lresult = synthesize_struct_layout(
          r.ctor_ea,
          vt.class_name,
          vt.vft_ea,
          true /* is_polymorphic: vt came from find_rtti_vtables() */);
      if ( lresult.resolved )
      {
        apply_layout_result(lresult);
        ++layout_resolved_count;
      }
      layouts.push_back(lresult);
    }
  }

  qstring log_path = write_scan_log(results, hierarchies, unresolved_hierarchy_vtables, layouts);

  msg(
      "SM Global Finder: scanned %d classes, resolved %d, unresolved %d. "
      "RTTI hierarchies resolved %d/%d. Struct layouts synthesized %d/%d. Log: %s\n",
      int(results.size()),
      int(resolved_count),
      int(results.size() - resolved_count),
      int(hierarchy_resolved_count),
      int(vtables.size()),
      int(layout_resolved_count),
      int(vtables.size()),
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
