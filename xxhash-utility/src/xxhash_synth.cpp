#include "xxhash_synth.h"

#include <typeinf.hpp>

namespace xxhash_utility
{

bool synthesize_and_replace(const xxhash_match_t &match)
{
  if ( match.matched_stmt == nullptr || match.hash_target == nullptr
    || match.input.data_ptr == nullptr || match.input.length == nullptr
    || match.seed_expr == nullptr )
  {
    return false;
  }

  tinfo_t rettype;
  if ( !rettype.create_simple_type(match.variant == XXHASH_64 ? BTF_UINT64 : BTF_UINT32) )
    return false;

  carglist_t *args = new carglist_t();
  args->resize(3);
  args->at(0).consume_cexpr(new cexpr_t(*match.input.data_ptr));
  args->at(1).consume_cexpr(new cexpr_t(*match.input.length));
  args->at(2).consume_cexpr(new cexpr_t(*match.seed_expr));

  cexpr_t *call = call_helper(rettype, args, match.variant == XXHASH_64 ? "XXH64" : "XXH32");
  if ( call == nullptr )
    return false;

  cexpr_t *asg = new cexpr_t();
  asg->op = cot_asg;
  asg->x = new cexpr_t(*match.hash_target);
  asg->y = call;
  asg->type = asg->x->type;
  asg->ea = match.matched_stmt->ea;

  cinsn_t *new_stmt = new cinsn_t();
  new_stmt->op = cit_expr;
  new_stmt->cexpr = asg;
  new_stmt->ea = match.matched_stmt->ea;

  match.matched_stmt->replace_by(new_stmt);
  return true;
}

} // namespace xxhash_utility
