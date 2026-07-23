#include "naming.h"
#include "lua_api_docs.h"

#include <map>

namespace
{

// Turns an owner/funcname piece into a valid identifier fragment: "sm.audio"
// -> "sm_audio", "getTpBonePos" -> unchanged.
qstring sanitize_ident(const qstring &s)
{
  qstring out = s;
  for ( size_t i = 0; i < out.length(); ++i )
  {
    char c = out[i];
    bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
    if ( !ok )
      out[i] = '_';
  }
  return out;
}

bool has_label(const qvector<name_label_t> &labels, const qstring &owner, const qstring &funcname)
{
  for ( const name_label_t &l : labels )
  {
    if ( l.owner == owner && l.funcname == funcname )
      return true;
  }
  return false;
}

} // namespace

qvector<final_name_t> build_final_names(const qvector<lua_func_reg_t> &regs)
{
  std::map<ea_t, qvector<size_t>> groups;
  for ( size_t i = 0; i < regs.size(); ++i )
    groups[regs[i].func_ea].push_back(i);

  qvector<final_name_t> out;
  out.reserve(groups.size());

  for ( const auto &kv : groups )
  {
    qvector<name_label_t> labels;
    for ( size_t idx : kv.second )
    {
      const lua_func_reg_t &r = regs[idx];
      if ( has_label(labels, r.owner, r.funcname) )
        continue;
      name_label_t label;
      label.owner = r.owner;
      label.is_userdata = r.is_userdata;
      label.funcname = r.funcname;
      labels.push_back(label);
    }

    final_name_t fin;
    fin.func_ea = kv.first;
    fin.labels = labels;

    fin.name = "Lua";
    for ( const name_label_t &l : labels )
    {
      fin.name.cat_sprnt(
          "_%s_%s",
          sanitize_ident(l.owner).c_str(),
          sanitize_ident(l.funcname).c_str());
    }

    for ( const name_label_t &l : labels )
    {
      const lua_api_doc_entry_t *doc = find_lua_api_doc(l.is_userdata, l.owner.c_str(), l.funcname.c_str());
      if ( doc == nullptr )
        continue;
      if ( !fin.comment.empty() )
        fin.comment += "\n\n";
      fin.comment.cat_sprnt(
          "%s.%s(%s)\n%s",
          l.owner.c_str(), l.funcname.c_str(),
          doc->params, doc->summary);
    }

    out.push_back(fin);
  }

  return out;
}
