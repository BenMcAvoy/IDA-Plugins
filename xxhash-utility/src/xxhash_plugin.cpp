// IDA-XXHash-Utility: recognizes compiler-inlined XXH32/XXH64 hashing
// routines in Hex-Rays pseudocode and collapses them into a single
// readable synthetic call. See
// C:\Users\Ben\.claude\plans\spicy-imagining-church.md for the design.

#include "xxhash_match.h"
#include "xxhash_synth.h"

#include <hexrays.hpp>
#include <diskio.hpp>
#include <fpro.h>

#include <cstdarg>
#include <set>

namespace
{

using namespace xxhash_utility;

void debug_log(const char *format, ...)
{
  qstring path;
  path.sprnt("%s/IDA-XXHash-Utility.log", get_user_idadir());
  FILE *file = qfopen(path.c_str(), "a");
  if ( file == nullptr )
    return;

  qstring message;
  va_list args;
  va_start(args, format);
  message.vsprnt(format, args);
  va_end(args);
  qfprintf(
    file,
    "[%u.%06u] %s\n",
    get_secs(qtime64()),
    get_usecs(qtime64()),
    message.c_str());
  qfclose(file);
}

// Runs at hxe_maturity/CMAT_FINAL (before Hex-Rays generates pseudocode
// text), mirroring the ctree-mutation timing of IDA-VTable-Utility's
// vtable_receiver_hider_t -- but here visit_insn (not visit_expr) is
// overridden, since the xxHash shape spans a whole if/if-else/do-while
// statement sequence, not a single expression.
struct xxhash_collapser_t : public ctree_visitor_t
{
  int collapsed_count = 0;

  xxhash_collapser_t() : ctree_visitor_t(CV_FAST) {}

  int idaapi visit_insn(cinsn_t *insn) override
  {
    if ( insn->op != cit_if )
      return 0;

    xxhash_match_t match;
    const char *variant_name = nullptr;
    if ( try_match_xxh32(insn, &match) )
      variant_name = "XXH32";
    else if ( try_match_xxh64(insn, &match) )
      variant_name = "XXH64";
    else
      return 0;

    if ( !synthesize_and_replace(match) )
    {
      debug_log("matched %s pattern at %a but failed to synthesize replacement", variant_name, insn->ea);
      return 0;
    }

    debug_log("collapsed %s pattern at %a", variant_name, insn->ea);
    ++collapsed_count;
    return 0;
  }
};

// Collects the lvar index of every cot_var reference remaining in the
// (already-mutated) ctree.
struct used_var_collector_t : public ctree_visitor_t
{
  std::set<int> used_indices;

  used_var_collector_t() : ctree_visitor_t(CV_FAST) {}

  int idaapi visit_expr(cexpr_t *e) override
  {
    if ( e->op == cot_var )
      used_indices.insert(e->v.idx);
    return 0;
  }
};

// replace_by() deletes the matched statements but leaves the collapsed
// pattern's now-orphaned locals (lane accumulators, the intermediate hash
// variable, the resolved data pointer, etc.) sitting in the function's
// variable list -- Hex-Rays would otherwise still declare them (unused)
// since their CVAR_USED flag was computed before our mutation and is never
// recalculated afterward. Clear it for anything no longer referenced
// anywhere in the final ctree, so only the final hash variable (and any
// other genuinely-still-used locals) remain visible. Function arguments
// are left untouched regardless of use, since hiding those would alter the
// printed function signature, not just a declaration line.
void hide_orphaned_locals(cfunc_t *cfunc)
{
  used_var_collector_t collector;
  collector.apply_to(&cfunc->body, nullptr);

  lvars_t *lvars = cfunc->get_lvars();
  if ( lvars == nullptr )
    return;

  for ( size_t i = 0; i < lvars->size(); ++i )
  {
    lvar_t &lvar = lvars->at(i);
    if ( lvar.is_arg_var() || !lvar.used() )
      continue;
    if ( collector.used_indices.find(int(i)) == collector.used_indices.end() )
      lvar.clear_used();
  }
}

ssize_t idaapi decompiler_callback(void *, hexrays_event_t event, va_list va)
{
  if ( event == hxe_maturity )
  {
    cfunc_t *cfunc = va_arg(va, cfunc_t *);
    const ctree_maturity_t new_maturity = ctree_maturity_t(va_arg(va, int));
    if ( new_maturity == CMAT_FINAL )
    {
      xxhash_collapser_t collapser;
      collapser.apply_to(&cfunc->body, nullptr);
      if ( collapser.collapsed_count > 0 )
      {
        hide_orphaned_locals(cfunc);
        debug_log(
          "function=%a collapsed=%d",
          cfunc->entry_ea,
          collapser.collapsed_count);
      }
    }
    return 0;
  }
  return 0;
}

struct xxhash_plugmod_t final : plugmod_t
{
  xxhash_plugmod_t()
  {
    if ( !install_hexrays_callback(decompiler_callback, this) )
      msg("%s: failed to install the Hex-Rays callback\n", PLUGIN.wanted_name);
    debug_log("plugin initialized: version=0.1.0");
  }

  ~xxhash_plugmod_t() override
  {
    remove_hexrays_callback(decompiler_callback, this);
  }

  bool idaapi run(size_t) override
  {
    return false;
  }
};

plugmod_t *idaapi init()
{
  if ( !init_hexrays_plugin() )
    return nullptr;
  return new xxhash_plugmod_t;
}

} // namespace

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_HIDE | PLUGIN_MULTI,
  init,
  nullptr,
  nullptr,
  "Recognizes compiler-inlined XXH32/XXH64 and collapses them into a readable call.",
  "",
  "IDA-XXHash-Utility",
  ""
};
