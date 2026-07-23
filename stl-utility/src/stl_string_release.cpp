#include "stl_string_release.h"

#include <typeinf.hpp>

#include <cstring>
#include <set>
#include <vector>

namespace stl_utility
{

namespace
{

// basic_string layout, per src/stl_string.cpp: _Bx at 0x00, _Mysize at 0x10,
// _Myres at 0x18, struct size 0x20.
constexpr uint32 MYRES_OFFSET = 0x18;

const cexpr_t *strip_casts(const cexpr_t *e)
{
  while ( e != nullptr && e->op == cot_cast )
    e = e->x;
  return e;
}

bool is_num32(const cexpr_t *e, uint32 value)
{
  return e != nullptr && e->op == cot_num && uint32(e->numval()) == value;
}

// True if `e` is `obj.<member at `offset`>` (a memref/memptr at `offset`).
// On success, *base is the object expression (`obj`).
bool match_member(const cexpr_t *e, uint32 offset, const cexpr_t **base)
{
  e = strip_casts(e);
  if ( e == nullptr || (e->op != cot_memref && e->op != cot_memptr) || e->m != offset )
    return false;
  *base = e->x;
  return true;
}

// True if `e` is `obj._Myres > 0xF` (signed or unsigned greater-than against
// the literal 0xF). This is MSVC's "is this string NOT using the inline SSO
// buffer" check -- the strict, distinctive backstop for this whole matcher.
// On success, *base is the string object expression (`obj`).
bool match_myres_gt_sso_threshold(const cexpr_t *e, const cexpr_t **base)
{
  e = strip_casts(e);
  if ( e == nullptr || (e->op != cot_sgt && e->op != cot_ugt) )
    return false;

  const cexpr_t *lhs = strip_casts(e->x);
  if ( !match_member(lhs, MYRES_OFFSET, base) )
    return false;

  return is_num32(strip_casts(e->y), 0xF);
}

// True if `parent_type` is a UDT (struct/union) with a member named
// `member_name` whose slot matches `access_m` under the access semantics
// Hex-Rays uses for that UDT kind. Per hexrays.hpp's cexpr_t::m doc
// comment: "member offset (used for cot_memptr, cot_memref) ... for
// unions, the member number" -- i.e. `m` is a BYTE OFFSET when the
// immediate parent is a plain struct, but an ORDINAL MEMBER INDEX when the
// immediate parent is a union. Resolving by name (rather than assuming a
// fixed offset/index) keeps this correct regardless of which convention
// applies at this layer, and regardless of exact member ordering/offsets
// in whatever build produced the type.
bool udt_member_matches(const tinfo_t &parent_type, uint32 access_m, const char *member_name)
{
  if ( !parent_type.is_udt() )
    return false;

  udt_type_data_t udt;
  if ( !parent_type.get_udt_details(&udt) )
    return false;

  if ( udt.is_union )
  {
    // Union: `m` is the member's ordinal index into the declaration order.
    return access_m < udt.size() && udt[access_m].name == member_name;
  }

  // Plain struct: `m` is a byte offset. Find the named member and compare
  // its byte offset (udm_t::offset is in BITS) against `access_m`.
  for ( size_t i = 0; i < udt.size(); ++i )
  {
    if ( udt[i].name == member_name )
      return access_m == uint32(udt[i].offset / 8);
  }
  return false;
}

// True if `e` is `parent.<member_name>` (a memref/memptr node whose
// immediate parent's UDT member list resolves `member_name` at slot
// `e->m`, per udt_member_matches()'s struct-offset-vs-union-index
// handling). On success, *base is the parent object expression.
bool match_named_member(const cexpr_t *e, const char *member_name, const cexpr_t **base)
{
  e = strip_casts(e);
  if ( e == nullptr || (e->op != cot_memref && e->op != cot_memptr) )
    return false;

  const cexpr_t *parent = strip_casts(e->x);
  if ( parent == nullptr )
    return false;

  tinfo_t parent_type = parent->type;
  if ( e->op == cot_memptr && parent_type.is_ptr() )
    parent_type = parent_type.get_pointed_object();

  if ( !udt_member_matches(parent_type, e->m, member_name) )
    return false;

  *base = parent;
  return true;
}

// True if `e` resolves to `obj._Bx._Ptr` after stripping casts: a two-level
// member-access chain where the first layer (`_Bx`, a plain-struct member
// of basic_string) and the second layer (`_Ptr`, a member of the anonymous
// `_Bxty` union) are each matched by NAME via match_named_member() --
// critically, NOT by assuming both layers use the same "cumulative byte
// offset" convention, since the union layer's `e->m` is an ordinal member
// index, not a byte offset (see match_named_member()/udt_member_matches()).
// Also tolerates Hex-Rays flattening the anonymous union access away
// entirely, in which case only one memref/memptr layer is present.
// On success, *base is the string object expression (`obj`).
bool match_bx_ptr_chain(const cexpr_t *e, const cexpr_t **base)
{
  const cexpr_t *ptr_base = nullptr;
  if ( match_named_member(e, "_Ptr", &ptr_base) )
  {
    const cexpr_t *bx_base = nullptr;
    if ( match_named_member(ptr_base, "_Bx", &bx_base) )
    {
      *base = bx_base;
      return true;
    }
    // Flattened case: Hex-Rays collapsed the `_Bx` union access away, so
    // `ptr_base` is already the string object itself.
    *base = ptr_base;
    return true;
  }

  // Fully-flattened fallback: a single memref/memptr straight at `_Bx`
  // (e.g. if Hex-Rays instead collapses the `_Ptr` union arm access away).
  const cexpr_t *bx_base = nullptr;
  if ( match_named_member(e, "_Bx", &bx_base) )
  {
    *base = bx_base;
    return true;
  }

  return false;
}

bool same_object(const cexpr_t *a, const cexpr_t *b)
{
  a = strip_casts(a);
  b = strip_casts(b);
  if ( a == nullptr || b == nullptr )
    return false;
  return a->equal_effect(*b);
}

// True if `e` resolves (tolerating Hex-Rays flattening the anonymous union
// access away, same fallback structure as match_bx_ptr_chain()) to
// `obj._Bx._Buf`. On success, *base is the string object expression (`obj`).
bool match_bx_buf_chain(const cexpr_t *e, const cexpr_t **base)
{
  const cexpr_t *buf_base = nullptr;
  if ( match_named_member(e, "_Buf", &buf_base) )
  {
    const cexpr_t *bx_base = nullptr;
    if ( match_named_member(buf_base, "_Bx", &bx_base) )
    {
      *base = bx_base;
      return true;
    }
    // Flattened case: Hex-Rays collapsed the `_Bx` union access away.
    *base = buf_base;
    return true;
  }

  // Fully-flattened fallback: a single memref/memptr straight at `_Bx`.
  const cexpr_t *bx_base = nullptr;
  if ( match_named_member(e, "_Bx", &bx_base) )
  {
    *base = bx_base;
    return true;
  }

  return false;
}

// True if `sib` is `obj.<member_name> = value` (a cit_expr wrapping a
// cot_asg) for the SAME object as `obj_expr` (per same_object()). Used to
// match the `_Mysize = 0` / `_Myres = 0xF` tail reset writes.
bool match_named_member_reset_write(
        const cinsn_t *sib,
        const cexpr_t *obj_expr,
        const char *member_name,
        uint32 value)
{
  if ( sib == nullptr || sib->op != cit_expr || sib->cexpr == nullptr )
    return false;

  const cexpr_t *asg = strip_casts(sib->cexpr);
  if ( asg == nullptr || asg->op != cot_asg )
    return false;

  const cexpr_t *base = nullptr;
  if ( !match_named_member(asg->x, member_name, &base) )
    return false;
  if ( !same_object(base, obj_expr) )
    return false;

  return is_num32(strip_casts(asg->y), value);
}

// True if `sib` is `obj._Bx._Buf[0] = 0` (the SSO buffer's first-byte
// null-terminator reset), for the SAME object as `obj_expr`.
bool match_buf_zero_write(const cinsn_t *sib, const cexpr_t *obj_expr)
{
  if ( sib == nullptr || sib->op != cit_expr || sib->cexpr == nullptr )
    return false;

  const cexpr_t *asg = strip_casts(sib->cexpr);
  if ( asg == nullptr || asg->op != cot_asg )
    return false;

  const cexpr_t *lhs = strip_casts(asg->x);
  if ( lhs == nullptr || lhs->op != cot_idx )
    return false;
  if ( !is_num32(strip_casts(lhs->y), 0) )
    return false;

  const cexpr_t *base = nullptr;
  if ( !match_bx_buf_chain(lhs->x, &base) )
    return false;
  if ( !same_object(base, obj_expr) )
    return false;

  return is_num32(strip_casts(asg->y), 0);
}

struct string_match_t
{
  cinsn_t *matched_stmt = nullptr;
  const cexpr_t *obj_expr = nullptr;
};

bool try_match_string_release(cinsn_t *outer_if, string_match_t *out)
{
  if ( outer_if == nullptr || outer_if->op != cit_if || outer_if->cif == nullptr )
    return false;
  if ( outer_if->cif->ielse != nullptr )
    return false;

  const cexpr_t *obj_expr = nullptr;
  if ( !match_myres_gt_sso_threshold(&outer_if->cif->expr, &obj_expr) )
    return false;

  cinsn_t *body = outer_if->cif->ithen;
  if ( body == nullptr || body->op != cit_block || body->cblock == nullptr )
    return false;

  std::vector<cinsn_t *> stmts;
  for ( cinsn_t &stmt : *body->cblock )
    stmts.push_back(&stmt);

  // Expected shape: [ptr = obj._Bx._Ptr;] (optional big-alloc-header
  // validation `if`;) free_call(ptr); -- i.e. 2 or 3 top-level statements.
  if ( stmts.size() != 2 && stmts.size() != 3 )
    return false;

  cinsn_t *assign_stmt = stmts.front();
  if ( assign_stmt->op != cit_expr || assign_stmt->cexpr == nullptr )
    return false;
  const cexpr_t *assign = assign_stmt->cexpr;
  if ( assign->op != cot_asg )
    return false;

  const cexpr_t *rhs_base = nullptr;
  if ( !match_bx_ptr_chain(assign->y, &rhs_base) )
    return false;
  if ( !same_object(obj_expr, rhs_base) )
    return false;

  cinsn_t *free_stmt = stmts.back();
  if ( free_stmt->op != cit_expr || free_stmt->cexpr == nullptr )
    return false;
  if ( strip_casts(free_stmt->cexpr)->op != cot_call )
    return false;

  // Middle statement (when present) is MSVC's big-allocation-header
  // validation `if`. Its exact inner shape (the 0x1000/0x1F constants, the
  // noreturn call) is deliberately NOT validated -- it's optional
  // boilerplate that only fires for very large allocations / checked
  // builds. We just require it to be an `if` so an unrelated statement
  // here doesn't get silently swallowed into the match.
  if ( stmts.size() == 3 && stmts[1]->op != cit_if )
    return false;

  out->matched_stmt = outer_if;
  out->obj_expr = obj_expr;
  return true;
}

// Best-effort std::string vs std::wstring distinction: if the object's
// resolved type name (set up by src/stl_string.cpp's retyping, e.g. the
// synthetic "__stl_string_wchar_sso" struct, or a real demangled
// std::wstring/basic_string<wchar_t,...> name) mentions "wchar"/"wstring",
// render as "~wstring(...)"; otherwise default to "~string(...)". If the
// object hasn't been retyped yet (still an opaque byte buffer / unresolved
// type), this can't distinguish char from wchar_t and falls back to
// "~string(...)".
bool looks_like_wide_string(const cexpr_t *obj_expr)
{
  if ( obj_expr == nullptr )
    return false;

  qstring type_name;
  if ( !obj_expr->type.print(&type_name) )
    return false;

  return type_name.find("wchar") != qstring::npos
      || type_name.find("wstring") != qstring::npos;
}

bool synthesize_and_replace(const string_match_t &match)
{
  if ( match.matched_stmt == nullptr || match.obj_expr == nullptr )
    return false;

  tinfo_t void_type;
  if ( !void_type.create_simple_type(BTF_VOID) )
    return false;

  carglist_t *args = new carglist_t();
  args->resize(1);
  args->at(0).consume_cexpr(new cexpr_t(*match.obj_expr));

  // Same rendering approach as stl_shared_ptr_release.cpp's
  // synthesize_and_replace(): a helper expression printed as "name(args...)"
  // is the closest achievable approximation of true "obj.~Type()" syntax
  // (Hex-Rays has no ctree construct for synthesizing the latter), and the
  // object argument is a real cloned cexpr_t -- clickable/renameable in the
  // pseudocode, not text baked into the helper name.
  const char *helper_name = looks_like_wide_string(match.obj_expr) ? "~wstring" : "~string";
  cexpr_t *call = call_helper(void_type, args, helper_name);
  if ( call == nullptr )
    return false;

  cinsn_t *new_stmt = new cinsn_t();
  new_stmt->op = cit_expr;
  new_stmt->cexpr = call;
  new_stmt->ea = match.matched_stmt->ea;

  match.matched_stmt->replace_by(new_stmt);
  return true;
}

// Scans whole cblock_t's (rather than single cit_if nodes in isolation) so
// it can see and remove the up-to-3 sibling reset-writes
// ("boneName._Mysize = 0; boneName._Myres = 15; boneName._Bx._Buf[0] = 0;")
// that MSVC emits immediately after the matched `if` -- these are true
// siblings in the surrounding block, not descendants of the `if`, so a
// single-node visit_insn(cit_if) override structurally cannot reach them.
struct string_release_collapser_t : public ctree_visitor_t
{
  int collapsed_count = 0;

  string_release_collapser_t() : ctree_visitor_t(CV_FAST) {}

  int idaapi visit_insn(cinsn_t *insn) override
  {
    if ( insn->op != cit_block || insn->cblock == nullptr )
      return 0;

    cblock_t &block = *insn->cblock;
    for ( cblock_t::iterator it = block.begin(); it != block.end(); ++it )
    {
      cinsn_t *stmt = &*it;
      if ( stmt->op != cit_if )
        continue;

      string_match_t match;
      if ( !try_match_string_release(stmt, &match) )
        continue;

      // Look at (up to) the next 3 sibling statements in the SAME block
      // for the reset-tail writes. Tolerate any subset and any order --
      // each candidate is tested against whichever of the three known
      // writes hasn't been consumed yet -- but never erase a sibling that
      // doesn't positively match one of them.
      bool consumed_size = false;
      bool consumed_res = false;
      bool consumed_buf = false;

      cblock_t::iterator scan = it;
      ++scan;
      for ( int i = 0; i < 3 && scan != block.end(); ++i )
      {
        cinsn_t *sib = &*scan;
        bool matched_reset = false;

        if ( !consumed_size && match_named_member_reset_write(sib, match.obj_expr, "_Mysize", 0) )
        {
          consumed_size = true;
          matched_reset = true;
        }
        else if ( !consumed_res && match_named_member_reset_write(sib, match.obj_expr, "_Myres", 0xF) )
        {
          consumed_res = true;
          matched_reset = true;
        }
        else if ( !consumed_buf && match_buf_zero_write(sib, match.obj_expr) )
        {
          consumed_buf = true;
          matched_reset = true;
        }

        if ( matched_reset )
        {
          cblock_t::iterator to_erase = scan;
          ++scan;
          block.erase(to_erase);
        }
        else
        {
          ++scan;
        }
      }

      if ( synthesize_and_replace(match) )
        ++collapsed_count;
    }
    return 0;
  }
};

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

// See stl_shared_ptr_release.cpp's hide_orphaned_locals() for the
// rationale: replace_by deletes statements but leaves now-orphaned locals
// (the cached heap pointer, e.g. "Ptr") declared-but-unused, since their
// CVAR_USED flag isn't recalculated after our mutation. Hide anything no
// longer referenced, skipping arguments (never hide those -- it would
// alter the printed function signature, not just a declaration line).
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

} // namespace

int collapse_string_releases(cfunc_t *cfunc)
{
  string_release_collapser_t collapser;
  collapser.apply_to(&cfunc->body, nullptr);
  if ( collapser.collapsed_count > 0 )
    hide_orphaned_locals(cfunc);
  return collapser.collapsed_count;
}

} // namespace stl_utility
