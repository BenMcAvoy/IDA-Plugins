import json, glob, os

SRC = os.path.join(os.path.dirname(__file__), "sm_api", "json")
OUT = os.path.join(os.path.dirname(__file__), "lua_api_docs.gen.cpp")

def esc(s):
    return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "")

def first_text(doc):
    if not doc:
        return ""
    for t in doc.get("text") or []:
        t = t.strip()
        if t and not t.startswith("@"):
            return t
    return ""

def param_sig(doc):
    parts = []
    for p in (doc or {}).get("params") or []:
        if len(p) >= 2:
            parts.append(f"{p[0]} {p[1]}")
    return ", ".join(parts)

# owner_kind: 0 = namespace (dotted, e.g. "sm.audio"), 1 = userdata (e.g. "Character")
entries = []  # (owner_kind, owner, funcname, params, summary)
seen = set()

for path in sorted(glob.glob(os.path.join(SRC, "namespace_Game_*.json"))):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    ns = data.get("namespace", "")
    for fn in data.get("functions", []) or []:
        name = fn.get("name", "")
        if not name:
            continue
        key = (0, ns, name)
        if key in seen:
            continue
        seen.add(key)
        doc = fn.get("doc") or {}
        entries.append((0, ns, name, param_sig(doc), first_text(doc)))

for path in sorted(glob.glob(os.path.join(SRC, "userdata_Game_*.json"))):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    ud = data.get("userdata", "")
    for fn in data.get("functions", []) or []:
        name = fn.get("name", "")
        if not name:
            continue
        key = (1, ud, name)
        if key in seen:
            continue
        seen.add(key)
        doc = fn.get("doc") or {}
        entries.append((1, ud, name, param_sig(doc), first_text(doc)))

entries.sort(key=lambda e: (e[0], e[1], e[2]))

with open(OUT, "w", encoding="utf-8") as f:
    f.write("// Generated from sm_api_differ json_ch1 dump (Game app: namespace_Game_*.json,\n")
    f.write("// userdata_Game_*.json). Do not edit by hand -- see gen_api_docs.py.\n")
    f.write("#include \"lua_api_docs.h\"\n\n")
    f.write("const lua_api_doc_entry_t g_lua_api_docs[] =\n{\n")
    for kind, owner, name, params, summary in entries:
        f.write(
            f'  {{ {kind}, "{esc(owner)}", "{esc(name)}", "{esc(params)}", "{esc(summary)}" }},\n'
        )
    f.write("};\n\n")
    f.write("const size_t g_lua_api_docs_count = sizeof(g_lua_api_docs) / sizeof(g_lua_api_docs[0]);\n")

print(f"Wrote {len(entries)} entries to {OUT}")
