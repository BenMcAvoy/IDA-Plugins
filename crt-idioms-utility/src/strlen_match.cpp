#include "strlen_match.h"

#include <typeinf.hpp>

#include <set>

namespace crt_idioms
{

namespace
{

const cexpr_t *strip_casts(const cexpr_t *e)
{
  while ( e != nullptr && e->op == cot_cast )
    e = e->x;
  return e;
}

bool is_num(const cexpr_t *e, int64 value)
{
  return e != nullptr && e->op == cot_num && int64(e->numval()) == value;
}

bool is_var(const cexpr_t *e, int var_idx)
{
  return e != nullptr && e->op == cot_var && e->v.idx == var_idx;
}

// If `body` is a cit_block with exactly one statement, returns that
// statement; if `body` itself isn't a block, returns it directly (a
// single, brace-less statement); otherwise (empty/multi-statement block)
// returns nullptr.
cinsn_t *single_body_stmt(cinsn_t *body)
{
  if ( body == nullptr )
    return nullptr;
  if ( body->op != cit_block )
    return body;
  if ( body->cblock == nullptr || body->cblock->size() != 1 )
    return nullptr;
  return &body->cblock->front();
}

// True if `stmt` (a cit_expr, possibly wrapping the whole statement) is one
// of:
//   ++counter;   / counter++;   (cot_preinc/cot_postinc on counter)
//   counter += 1;               (cot_asgadd, since Hex-Rays sometimes prints
//                                 "x += 1" as a distinct opcode rather than
//                                 folding it into cot_preinc/cot_postinc --
//                                 lesson learned in IDA-XXHash-Utility)
bool match_increment(cinsn_t *stmt, int counter_idx)
{
  if ( stmt == nullptr || stmt->op != cit_expr || stmt->cexpr == nullptr )
    return false;

  const cexpr_t *e = stmt->cexpr;
  if ( e->op == cot_preinc || e->op == cot_postinc )
    return is_var(strip_casts(e->x), counter_idx);

  if ( e->op == cot_asgadd )
    return is_var(strip_casts(e->x), counter_idx) && is_num(strip_casts(e->y), 1);

  return false;
}

// If `binop` is `PTR + counter` or `counter + PTR` (a cot_add/cot_idx whose
// operands are, in either order, a pointer expression and the counter
// var), returns the pointer-expression operand; otherwise nullptr.
const cexpr_t *match_ptr_plus_counter(const cexpr_t *binop, int counter_idx)
{
  if ( binop == nullptr || binop->x == nullptr || binop->y == nullptr )
    return nullptr;
  if ( is_var(strip_casts(binop->x), counter_idx) )
    return binop->y;
  if ( is_var(strip_casts(binop->y), counter_idx) )
    return binop->x;
  return nullptr;
}

// True if `cond` (the do-while's trailing condition) is a truthiness test
// on `*(_BYTE *)(ptr + counter)`, tolerating both the bare deref (used
// directly as a truthy condition) and an explicit "!= 0" comparison. On
// success, returns the recovered pointer sub-expression (still owned by
// the ctree -- caller must clone before reusing it elsewhere).
const cexpr_t *match_byte_deref_condition(const cexpr_t *cond, int counter_idx)
{
  const cexpr_t *e = strip_casts(cond);
  if ( e == nullptr )
    return nullptr;

  if ( e->op == cot_ne )
  {
    const cexpr_t *a = strip_casts(e->x);
    const cexpr_t *b = strip_casts(e->y);
    const cexpr_t *deref = nullptr;
    if ( is_num(a, 0) )
      deref = e->y;
    else if ( is_num(b, 0) )
      deref = e->x;
    if ( deref == nullptr )
      return nullptr;
    e = strip_casts(deref);
  }
  if ( e == nullptr )
    return nullptr;

  if ( e->op == cot_ptr )
  {
    const cexpr_t *inner = strip_casts(e->x);
    if ( inner == nullptr || inner->op != cot_add )
      return nullptr;
    return match_ptr_plus_counter(inner, counter_idx);
  }
  if ( e->op == cot_idx )
    return match_ptr_plus_counter(e, counter_idx);

  return nullptr;
}

struct strlen_match_t
{
  cinsn_t *asg_stmt = nullptr;      // "counter = -1;"
  cinsn_t *do_stmt = nullptr;       // the sibling do-while right after it
  const cexpr_t *counter_var = nullptr; // the cot_var LHS of asg_stmt (for cloning)
  const cexpr_t *ptr_expr = nullptr;    // recovered string pointer (for cloning)
};

// Matches the "counter = -1;" / "do ++counter; while (*(ptr+counter));"
// pair of adjacent statements. `asg_stmt` and `do_stmt` must already be
// known to be adjacent siblings within the same cblock_t.
bool try_match_pair(cinsn_t *asg_stmt, cinsn_t *do_stmt, strlen_match_t *out)
{
  if ( asg_stmt == nullptr || asg_stmt->op != cit_expr || asg_stmt->cexpr == nullptr )
    return false;

  const cexpr_t *asg = asg_stmt->cexpr;
  if ( asg->op != cot_asg )
    return false;

  const cexpr_t *lhs = strip_casts(asg->x);
  if ( lhs == nullptr || lhs->op != cot_var )
    return false;

  const cexpr_t *rhs = strip_casts(asg->y);
  if ( rhs == nullptr || rhs->op != cot_num || int64(rhs->numval()) != -1 )
    return false;

  const int counter_idx = lhs->v.idx;

  if ( do_stmt == nullptr || do_stmt->op != cit_do || do_stmt->cdo == nullptr )
    return false;

  cinsn_t *inc_stmt = single_body_stmt(do_stmt->cdo->body);
  if ( !match_increment(inc_stmt, counter_idx) )
    return false;

  const cexpr_t *ptr_expr = match_byte_deref_condition(&do_stmt->cdo->expr, counter_idx);
  if ( ptr_expr == nullptr )
    return false;

  out->asg_stmt = asg_stmt;
  out->do_stmt = do_stmt;
  out->counter_var = lhs;
  out->ptr_expr = ptr_expr;
  return true;
}

bool synthesize_and_replace(const strlen_match_t &match)
{
  if ( match.asg_stmt == nullptr || match.counter_var == nullptr || match.ptr_expr == nullptr )
    return false;

  tinfo_t int_type;
  if ( !int_type.create_simple_type(BTF_INT32) )
    return false;

  carglist_t *args = new carglist_t();
  args->resize(1);
  args->at(0).consume_cexpr(new cexpr_t(*match.ptr_expr));

  cexpr_t *call = call_helper(int_type, args, "strlen");
  if ( call == nullptr )
    return false;

  cexpr_t *counter_clone = new cexpr_t(*match.counter_var);

  cexpr_t *assign = new cexpr_t();
  assign->op = cot_asg;
  assign->x = counter_clone;
  assign->y = call;
  assign->type = counter_clone->type;
  assign->exflags = 0;

  cinsn_t *new_stmt = new cinsn_t();
  new_stmt->op = cit_expr;
  new_stmt->cexpr = assign;
  new_stmt->ea = match.asg_stmt->ea;

  match.asg_stmt->replace_by(new_stmt);
  return true;
}

struct strlen_collapser_t : public ctree_visitor_t
{
  int collapsed_count = 0;

  strlen_collapser_t() : ctree_visitor_t(CV_FAST) {}

  int idaapi visit_insn(cinsn_t *insn) override
  {
    if ( insn->op != cit_block || insn->cblock == nullptr )
      return 0;

    cblock_t *block = insn->cblock;
    for ( cblock_t::iterator it = block->begin(); it != block->end(); )
    {
      cblock_t::iterator next_it = it;
      ++next_it;
      if ( next_it == block->end() )
        break;

      strlen_match_t match;
      if ( try_match_pair(&*it, &*next_it, &match) && synthesize_and_replace(match) )
      {
        ++collapsed_count;
        // The assignment statement (`it`) was mutated in-place via
        // replace_by(); the do-while sibling (`next_it`) is now dead
        // weight and must be erased from the block, not left behind.
        it = block->erase(next_it);
        continue;
      }

      ++it;
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

// See IDA-STL-Utility's stl_shared_ptr_release.cpp for the rationale:
// replace_by/erase deletes statements but leaves now-orphaned locals (the
// loop counter, cached pointer, etc.) declared-but-unused, since their
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

int collapse_strlen_idioms(cfunc_t *cfunc)
{
  strlen_collapser_t collapser;
  collapser.apply_to(&cfunc->body, nullptr);
  if ( collapser.collapsed_count > 0 )
    hide_orphaned_locals(cfunc);
  return collapser.collapsed_count;
}

} // namespace crt_idioms
