#include "reg_scan.h"
#include "naming.h"
#include "lua_argcount_collapse.h"

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

qstring join_labels(const qvector<name_label_t> &labels)
{
  qstring out;
  for ( size_t i = 0; i < labels.size(); ++i )
  {
    if ( i != 0 )
      out += ", ";
    out.cat_sprnt("%s.%s", labels[i].owner.c_str(), labels[i].funcname.c_str());
  }
  return out;
}

struct scan_results_popup_t final : chooser_t
{
  static const int widths[];
  static const char *const headers[];

  const qvector<final_name_t> &results;

  explicit scan_results_popup_t(const qvector<final_name_t> &results_)
    : chooser_t(
        CH_MODAL | CH_KEEP,
        4,
        widths,
        headers,
        "SM Lua Function Finder Results"),
      results(results_)
  {
  }

  size_t idaapi get_count() const override
  {
    return results.size();
  }

  ea_t idaapi get_ea(size_t n) const override
  {
    return results[n].func_ea;
  }

  void idaapi get_row(
        qstrvec_t *cols_,
        int *,
        chooser_item_attrs_t *,
        size_t n) const override
  {
    const final_name_t &r = results[n];
    qstrvec_t &cols = *cols_;
    cols[0].sprnt("%a", r.func_ea);
    cols[1] = r.name;
    cols[2] = join_labels(r.labels);
    cols[3] = r.comment.empty() ? "-" : "yes";
  }
};

const int scan_results_popup_t::widths[] =
{
  CHCOL_HEX | 16,
  50,
  50,
  6,
};

const char *const scan_results_popup_t::headers[] =
{
  "Address",
  "New Name",
  "Owner(s).Function",
  "Doc",
};

// -------------------------------------------------------------------------
// Applying results
// -------------------------------------------------------------------------

func_t *ensure_func(ea_t ea)
{
  func_t *pfn = get_func(ea);
  if ( pfn != nullptr )
    return pfn;
  if ( add_func(ea) )
    return get_func(ea);
  return nullptr;
}

// Writes one line per renamed function to a log file next to the current
// database, so results survive after the modal chooser is closed.
qstring write_scan_log(const qvector<final_name_t> &results, const qstring &scan_log)
{
  char dir[QMAXPATH];
  qdirname(dir, sizeof(dir), get_path(PATH_TYPE_IDB));

  qstring log_path;
  log_path.sprnt("%s/sm_lua_func_finder_scan.log", dir);

  FILE *fp = qfopen(log_path.c_str(), "w");
  if ( fp == nullptr )
    return qstring();

  qfprintf(fp, "=== Diagnostics from the scan pass ===\n%s\n", scan_log.c_str());
  qfprintf(fp, "=== Renamed functions ===\n");
  for ( const final_name_t &r : results )
  {
    qfprintf(
        fp,
        "%a  %-60s  %s\n",
        r.func_ea,
        r.name.c_str(),
        join_labels(r.labels).c_str());
  }

  qfclose(fp);
  return log_path;
}

// -------------------------------------------------------------------------
// Live decompiler collapse hook
// -------------------------------------------------------------------------

// Fires once per decompiled function, right before Hex-Rays finalizes its
// ctree into pseudocode text. Mirrors IDA-STL-Utility's stl_retype.cpp
// wiring: a single callback installed via install_hexrays_callback(),
// dispatching on the hexrays_event_t passed through the va_list.
ssize_t idaapi decompiler_callback(void *, hexrays_event_t event, va_list va)
{
  if ( event == hxe_maturity )
  {
    cfunc_t *cfunc = va_arg(va, cfunc_t *);
    const ctree_maturity_t new_maturity = ctree_maturity_t(va_arg(va, int));
    if ( new_maturity == CMAT_FINAL )
    {
      const int collapsed = collapse_lua_argcount_checks(cfunc);
      if ( collapsed > 0 )
        msg("SM Lua Function Finder: collapsed %d argcount check(s) in function=%a\n", collapsed, cfunc->entry_ea);
    }
    return 0;
  }

  return 0;
}

bool idaapi run(size_t)
{
  qstring log;
  qvector<lua_func_reg_t> regs = scan_lua_registrations(&log);
  if ( regs.empty() )
  {
    warning(
        "SM Lua Function Finder: no luaL_register()-based Lua function "
        "registrations were found in this database.\n\n%s",
        log.c_str());
    return true;
  }

  qvector<final_name_t> finals = build_final_names(regs);

  size_t renamed_count = 0;
  size_t commented_count = 0;
  for ( const final_name_t &r : finals )
  {
    func_t *pfn = ensure_func(r.func_ea);
    if ( pfn == nullptr )
    {
      log.cat_sprnt("SKIP rename at %a: couldn't create/find a function there\n", r.func_ea);
      continue;
    }

    if ( set_name(r.func_ea, r.name.c_str(), SN_FORCE | SN_NOWARN) )
      ++renamed_count;

    if ( !r.comment.empty() && set_func_cmt(pfn, r.comment.c_str(), true) )
      ++commented_count;
  }

  qstring log_path = write_scan_log(finals, log);

  msg(
      "SM Lua Function Finder: found %d Lua-registered function(s) across %d "
      "distinct addresses, renamed %d, added %d doc comment(s). Log: %s\n",
      int(regs.size()),
      int(finals.size()),
      int(renamed_count),
      int(commented_count),
      log_path.empty() ? "<failed to write>" : log_path.c_str());

  scan_results_popup_t popup(finals);
  popup.choose();
  return true;
}

plugmod_t *idaapi init()
{
  if ( !init_hexrays_plugin() )
    return nullptr;
  if ( !install_hexrays_callback(decompiler_callback, nullptr) )
    msg("%s: failed to install the Hex-Rays callback\n", PLUGIN.wanted_name);
  return PLUGIN_OK;
}

void idaapi term()
{
  remove_hexrays_callback(decompiler_callback, nullptr);
}

} // namespace

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,
  init,
  term,
  run,
  "Discovers Lua-callable C functions registered via luaL_register() "
  "(sm.* namespaces and userdata methods) and renames them Lua_<Owner>_<func>, "
  "using the sm_api_differ json dump for doc comments where available.",
  "",
  "SM Lua Function Finder",
  ""
};
