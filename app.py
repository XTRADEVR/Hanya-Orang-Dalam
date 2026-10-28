import os, shlex, subprocess, json
from pathlib import Path
from html import escape
import streamlit as st
import streamlit.components.v1 as components

st.set_page_config(page_title="Web Terminal PRO V4", page_icon="💻", layout="wide")
BASE_DIR = Path(__file__).resolve().parent
SANDBOX = BASE_DIR / "sandbox"
SANDBOX.mkdir(exist_ok=True)
SAFE_ENV = {"PATH": os.environ.get("PATH","/usr/bin:/bin"), "HOME": str(SANDBOX)}
HELP_TEXT = "help | clear | pwd | cd | ls | cat | mkdir | touch | rm | edit | echo | python"

def current_dir():
    p = (SANDBOX / st.session_state.cwd).resolve()
    return p if str(p).startswith(str(SANDBOX)) else SANDBOX

def rel_cwd():
    try:
        r = current_dir().relative_to(SANDBOX)
        return "~" if str(r)=="." else f"~/{r}"
    except: return "~"

for k,v in {"history":[],"cwd":".","editing":None,"edit_initial":"","up_nonce":0,"preview":None}.items():
    if k not in st.session_state: st.session_state[k]=v

css="<style>.stApp{background:#000}.term-box{background:#000;border:1px solid #1f6f1f;border-radius:8px;height:45vh;overflow-y:auto;display:flex;flex-direction:column-reverse;padding:12px}.term-inner{font-family:monospace;color:#39ff14;white-space:pre-wrap}</style>"
st.markdown(css,unsafe_allow_html=True)
st.markdown("### Web Terminal PRO V4 - PERTAHANAN + PREVIEW")

def terminal_html():
    parts=['<span>Terminal siap. Ketik help</span>\n']
    for h in st.session_state.history:
        parts.append(f'<span>{escape(h["cwd"])}$ {escape(h["cmd"])}</span>\n')
        for t in h["segs"]: parts.append(escape(t[1]))
    return "".join(parts)

st.markdown(f'<div class="term-box"><div class="term-inner">{terminal_html()}</div></div>',unsafe_allow_html=True)

def add_out(entry, text): entry["segs"].append(["out",text])

with st.form("cmd_form",clear_on_submit=True):
    c1,c2=st.columns([8,1])
    txt=c1.text_input("cmd",label_visibility="collapsed",placeholder=f"{rel_cwd()}$")
    sub=c2.form_submit_button("Run")

if sub and txt.strip():
    line=txt.strip()
    try: tokens=shlex.split(line)
    except: tokens=[]
    entry={"cwd":rel_cwd(),"cmd":line,"segs":[]}
    if not tokens:
        pass
    elif tokens[0]=="help":
        add_out(entry, HELP_TEXT+"\n")
        st.session_state.history.append(entry)
    elif tokens[0]=="clear":
        st.session_state.history=[]
    elif tokens[0]=="pwd":
        add_out(entry, rel_cwd()+"\n")
        st.session_state.history.append(entry)
    elif tokens[0]=="cd":
        target=tokens[1] if len(tokens)>1 else "~"
        new=SANDBOX if target=="~" else (current_dir()/target).resolve()
        if str(new).startswith(str(SANDBOX)) and new.is_dir():
            st.session_state.cwd=str(new.relative_to(SANDBOX))
        add_out(entry,"")
        st.session_state.history.append(entry)
    elif tokens[0]=="ls":
        try:
            out="\n".join([p.name for p in current_dir().iterdir()])
            add_out(entry,out+"\n")
        except Exception as e: add_out(entry,str(e))
        st.session_state.history.append(entry)
    elif tokens[0]=="edit":
        if len(tokens)<2:
            add_out(entry,"pakai: edit namafile\n")
            st.session_state.history.append(entry)
        else:
            fname=tokens[1]
            fpath=(current_dir()/fname)
            content=""
            if fpath.exists():
                try: content=fpath.read_text()
                except: content=""
            st.session_state.editing=str(fpath)
            st.session_state.edit_initial=content
            st.session_state.preview=None
            add_out(entry,f"membuka editor {fname}\n")
            st.session_state.history.append(entry)
    elif tokens[0] in ("cat","mkdir","touch","rm","echo"):
        try:
            r=subprocess.run(tokens,cwd=str(current_dir()),capture_output=True,timeout=5,text=True,env=SAFE_ENV)
            add_out(entry,r.stdout+r.stderr)
        except Exception as e: add_out(entry,str(e))
        st.session_state.history.append(entry)
    else:
        try:
            r=subprocess.run(tokens,cwd=str(current_dir()),capture_output=True,timeout=5,text=True,env=SAFE_ENV)
            add_out(entry,r.stdout+r.stderr or f"{tokens[0]}: tidak ditemukan\n")
        except Exception as e: add_out(entry,str(e))
        st.session_state.history.append(entry)
    st.rerun()

# EDITOR - DIPERTAHANKAN
if st.session_state.editing:
    st.markdown(f"#### ✏️ Editing {Path(st.session_state.editing).name}")
    new_content=st.text_area("editor",value=st.session_state.edit_initial,height=400,key="editor_area")
    c1,c2=st.columns(2)
    if c1.button("💾 Simpan"):
        try:
            Path(st.session_state.editing).write_text(new_content)
            st.toast("Tersimpan!")
            st.session_state.editing=None
            st.rerun()
        except Exception as e: st.error(str(e))
    if c2.button("❌ Batal"):
        st.session_state.editing=None
        st.rerun()

# PREVIEW - TAMBAHAN BARU, LAMA TETAP ADA
if st.session_state.preview:
    st.markdown(f"#### 👁️ Preview {Path(st.session_state.preview).name}")
    try:
        html_data=Path(st.session_state.preview).read_text()
        components.html(html_data,height=600,scrolling=True)
    except Exception as e:
        st.error(f"Gagal preview: {e}")
    if st.button("❌ Tutup Preview"):
        st.session_state.preview=None
        st.rerun()

# FILE MANAGER - DIPERTAHANKAN + TAMBAH PREVIEW
st.markdown("---")
st.markdown(f"#### 📁 File Manager - {rel_cwd()}")
ups=st.file_uploader("Upload (max 10MB)",accept_multiple_files=True,key=f"up_{st.session_state.up_nonce}")
if ups:
    for f in ups:
        (current_dir()/Path(f.name).name).write_bytes(f.getvalue())
    st.session_state.up_nonce+=1
    st.rerun()

for p in sorted(current_dir().iterdir()):
    c1,c2,c3,c4=st.columns([3,1,1,1])
    c1.markdown(f"{'📁' if p.is_dir() else '📄'} {p.name}")
    if not p.is_dir():
        try: c2.download_button("⬇️",data=p.read_bytes(),file_name=p.name,key=f"dl_{p.name}")
        except: pass
        if p.suffix.lower() in [".html",".htm"]:
            if c3.button("👁️",key=f"prev_{p.name}"):
                st.session_state.preview=str(p)
                st.session_state.editing=None
                st.rerun()
        if c4.button("🗑️",key=f"del_{p.name}"):
            p.unlink()
            st.rerun()
    else:
        if c2.button("📂 Buka",key=f"open_{p.name}"):
            st.session_state.cwd=str(p.relative_to(SANDBOX))
            st.rerun()

if st.button("🧹 Clear Terminal"): st.session_state.history=[]; st.rerun()
