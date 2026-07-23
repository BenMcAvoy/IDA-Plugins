// IDA-STL-Utility: one-click MSVC STL container retyping and content
// preview for Hex-Rays pseudocode. Mirrors the build/plugin conventions of
// the sister IDA-VTable-Utility plugin. See
// C:\Users\Ben\.claude\plans\spicy-imagining-church.md for the design.

#include "stl_registry.h"
#include "stl_memory.h"
#include "stl_shared_ptr_release.h"
#include "stl_string_release.h"
#include "stl_function_release.h"
#include "stl_vector_release.h"
#include "stl_util.h"

#include <hexrays.hpp>
#include <kernwin.hpp>
#include <name.hpp>
#include <typeinf.hpp>

#include <map>
#include <vector>

namespace
{

using namespace stl_utility;

constexpr char ACTION_NAME[] = "stl_retype:retype";
constexpr char ACTION_LABEL[] = "Retype as STL container";
constexpr char ACTION_HOTKEY[] = "Ctrl-Shift-T";
constexpr char POPUP_PATH[] = "IDA-STL-Utility/";

void append_colored(qstring *output, const char *text, const char *color)
{
  output->append(SCOLOR_ON);
  output->append(color);
  output->append(text);
  output->append(SCOLOR_OFF);
  output->append(color);
}

// Resolves what's under the cursor to either an lvar or a global address,
// plus its current (possibly empty/void) type.
struct retype_target_t
{
  lvar_t *lvar = nullptr;
  ea_t ea = BADADDR;
  tinfo_t existing_type;
};

bool resolve_target(vdui_t *vu, retype_target_t *out)
{
  if ( vu == nullptr || vu->item.citype != VDI_EXPR || vu->item.e == nullptr )
    return false;

  cexpr_t *e = vu->item.e;
  if ( e->op == cot_var )
  {
    out->lvar = &e->v.getv();
    out->ea = BADADDR;
    out->existing_type = out->lvar->type();
    return true;
  }
  if ( e->op == cot_obj )
  {
    out->lvar = nullptr;
    out->ea = e->obj_ea;
    get_tinfo(&out->existing_type, out->ea);
    return true;
  }
  return false;
}

struct candidate_t
{
  const stl_type_descriptor_t *descriptor;
  match_confidence_t confidence;
};

std::vector<candidate_t> collect_candidates(const tinfo_t &existing_type, const qstring &hint)
{
  std::vector<candidate_t> candidates;
  const tinfo_t *type_ptr = existing_type.empty() ? nullptr : &existing_type;
  const qstring *hint_ptr = hint.empty() ? nullptr : &hint;
  for ( const stl_type_descriptor_t *descriptor : get_stl_descriptor_registry() )
  {
    const match_confidence_t confidence = descriptor->matches(type_ptr, hint_ptr);
    if ( confidence != MATCH_NONE )
      candidates.push_back({ descriptor, confidence });
  }
  return candidates;
}

// Picks one descriptor among several candidates via a simple numbered
// prompt (ask_long), since a single high-confidence match wasn't found.
const stl_type_descriptor_t *choose_candidate(const std::vector<candidate_t> &candidates)
{
  if ( candidates.size() == 1 )
    return candidates[0].descriptor;

  qstring prompt = "Multiple/ambiguous STL types could apply. Pick one:\n";
  for ( size_t i = 0; i < candidates.size(); ++i )
    prompt.cat_sprnt("%d) %s\n", int(i + 1), candidates[i].descriptor->display_name);

  sval_t choice = 1;
  if ( !ask_long(&choice, "%s", prompt.c_str()) )
    return nullptr;
  if ( choice < 1 || size_t(choice) > candidates.size() )
  {
    warning("IDA-STL-Utility: invalid selection");
    return nullptr;
  }
  return candidates[size_t(choice) - 1].descriptor;
}

bool perform_retype(vdui_t *vu)
{
  retype_target_t target;
  if ( !resolve_target(vu, &target) )
  {
    warning("IDA-STL-Utility: place the cursor on a variable or global to retype");
    return false;
  }

  const qstring hint = printable_type_name(target.existing_type);
  const std::vector<candidate_t> candidates = collect_candidates(target.existing_type, hint);
  if ( candidates.empty() )
  {
    warning("IDA-STL-Utility: no supported STL type recognized for this item");
    return false;
  }

  size_t high_count = 0;
  for ( const candidate_t &c : candidates )
    high_count += (c.confidence == MATCH_HIGH) ? 1 : 0;

  const stl_type_descriptor_t *chosen = nullptr;
  if ( high_count == 1 )
  {
    for ( const candidate_t &c : candidates )
    {
      if ( c.confidence == MATCH_HIGH )
      {
        chosen = c.descriptor;
        break;
      }
    }
  }
  else
  {
    chosen = choose_candidate(candidates);
  }

  if ( chosen == nullptr )
    return false;

  tinfo_t resolved_type;
  qstring resolved_name;
  const tinfo_t *type_ptr = target.existing_type.empty() ? nullptr : &target.existing_type;
  const qstring *hint_ptr = hint.empty() ? nullptr : &hint;
  if ( !chosen->build_or_get_type(nullptr, type_ptr, hint_ptr, &resolved_type, &resolved_name) )
  {
    warning("IDA-STL-Utility: could not resolve the %s type", chosen->display_name);
    return false;
  }

  bool applied = false;
  if ( target.lvar != nullptr )
    applied = vu->set_lvar_type(target.lvar, resolved_type);
  else
    applied = apply_tinfo(target.ea, resolved_type, TINFO_DEFINITE);

  if ( !applied )
  {
    warning("IDA-STL-Utility: failed to apply type %s", resolved_name.c_str());
    return false;
  }

  debug_log(
    "retype: descriptor=%s target=%s applied_type=%s",
    chosen->key,
    target.lvar != nullptr ? target.lvar->name.c_str() : "<global>",
    resolved_name.c_str());

  vu->refresh_view(true);
  return true;
}

struct retype_action_t final : action_handler_t
{
  int idaapi activate(action_activation_ctx_t *ctx) override
  {
    if ( ctx == nullptr || ctx->widget_type != BWN_PSEUDOCODE )
      return 0;
    return perform_retype(get_widget_vdui(ctx->widget)) ? 1 : 0;
  }

  action_state_t idaapi update(action_update_ctx_t *ctx) override
  {
    return ctx != nullptr && ctx->widget_type == BWN_PSEUDOCODE
         ? AST_ENABLE_FOR_WIDGET
         : AST_DISABLE_FOR_WIDGET;
  }
};

retype_action_t g_retype_action;

// Appends a rendered content-preview comment to every printed line whose
// underlying variable/global is currently typed as one of our recognized
// STL containers (MATCH_HIGH only -- ambiguous/ill-defined matches are not
// auto-rendered to avoid noisy false positives on unrelated same-size
// structs). Runs once per hxe_func_printed pass.
struct preview_visitor_t : public ctree_visitor_t
{
  cfunc_t *cfunc;
  std::map<int, qstring> line_comments;

  explicit preview_visitor_t(cfunc_t *f) : ctree_visitor_t(CV_FAST), cfunc(f) {}

  int idaapi visit_expr(cexpr_t *e) override
  {
    if ( e->op != cot_var && e->op != cot_obj )
      return 0;

    tinfo_t type;
    ea_t instance_ea = BADADDR;
    if ( e->op == cot_var )
    {
      type = e->v.getv().type();
    }
    else
    {
      instance_ea = e->obj_ea;
      get_tinfo(&type, instance_ea);
    }

    if ( type.empty() )
      return 0;

    const qstring hint = printable_type_name(type);
    for ( const stl_type_descriptor_t *descriptor : get_stl_descriptor_registry() )
    {
      if ( descriptor->matches(&type, &hint) != MATCH_HIGH )
        continue;

      const stl_decode_result_t decoded = descriptor->decode_preview(instance_ea, type);
      if ( !decoded.ok || decoded.preview.empty() )
        break;

      int x = 0, y = 0;
      if ( !cfunc->find_item_coords(e, &x, &y) || y < 0 || y >= cfunc->sv.size() )
        break;

      qstring &slot = line_comments[y];
      if ( !slot.empty() )
        slot.append("; ");
      slot.append(decoded.preview);
      break;
    }
    return 0;
  }
};

void render_content_previews(cfunc_t *cfunc)
{
  preview_visitor_t visitor(cfunc);
  visitor.apply_to(&cfunc->body, nullptr);

  for ( const auto &entry : visitor.line_comments )
  {
    simpleline_t &line = cfunc->sv[entry.first];
    append_colored(&line.line, "  // ", SCOLOR_AUTOCMT);
    append_colored(&line.line, entry.second.c_str(), SCOLOR_AUTOCMT);
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
      const int collapsed = collapse_shared_ptr_releases(cfunc);
      if ( collapsed > 0 )
        debug_log("collapsed %d shared_ptr release sequence(s) in function=%a", collapsed, cfunc->entry_ea);

      const int collapsed_strings = collapse_string_releases(cfunc);
      if ( collapsed_strings > 0 )
        debug_log("collapsed %d string release sequence(s) in function=%a", collapsed_strings, cfunc->entry_ea);

      const int collapsed_functions = collapse_function_releases(cfunc);
      if ( collapsed_functions > 0 )
        debug_log("collapsed %d function release sequence(s) in function=%a", collapsed_functions, cfunc->entry_ea);

      const int collapsed_vectors = collapse_vector_releases(cfunc);
      if ( collapsed_vectors > 0 )
        debug_log("collapsed %d vector release sequence(s) in function=%a", collapsed_vectors, cfunc->entry_ea);
    }
    return 0;
  }

  if ( event == hxe_func_printed )
  {
    render_content_previews(va_arg(va, cfunc_t *));
    return 0;
  }

  if ( event == hxe_populating_popup )
  {
    TWidget *widget = va_arg(va, TWidget *);
    TPopupMenu *popup = va_arg(va, TPopupMenu *);
    va_arg(va, vdui_t *); // vu, unused: the action is always offered in pseudocode
    attach_action_to_popup(widget, popup, ACTION_NAME, POPUP_PATH);
    return 0;
  }

  return 0;
}

struct stl_retype_plugmod_t final : plugmod_t
{
  stl_retype_plugmod_t()
  {
    const action_desc_t desc = ACTION_DESC_LITERAL_PLUGMOD(
      ACTION_NAME,
      ACTION_LABEL,
      &g_retype_action,
      this,
      ACTION_HOTKEY,
      "Detect and apply the correct MSVC STL container type, with SSO-aware content preview",
      -1);

    if ( !register_action(desc) )
      msg("%s: failed to register action %s\n", PLUGIN.wanted_name, ACTION_NAME);

    if ( !install_hexrays_callback(decompiler_callback, this) )
      msg("%s: failed to install the Hex-Rays callback\n", PLUGIN.wanted_name);

    debug_log("plugin initialized: version=0.1.0");
  }

  ~stl_retype_plugmod_t() override
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
  return new stl_retype_plugmod_t;
}

} // namespace

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_HIDE | PLUGIN_MULTI,
  init,
  nullptr,
  nullptr,
  "One-click retyping and SSO-aware content preview for MSVC STL containers.",
  "",
  "IDA-STL-Utility",
  ""
};
