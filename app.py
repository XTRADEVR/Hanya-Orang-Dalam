import codecs, hmac, json, os, queue, re, shlex, signal, subprocess, sys, threading, time
from html import escape
from pathlib import Path
import streamlit as st

st.set_page_config(page_title="Web Terminal + File Manager", page_icon="💻", layout="wide")
BASE_DIR = Path(__file__).resolve().parent
SANDBOX = BASE_DIR / "sandbox"
SANDBOX.mkdir(exist_ok=True)
HISTORY_FILE = BASE_DIR / "terminal_history.json"
PERSIST_HISTORY = True
TIMEOUT_SECONDS = 10
MAX_RUNTIME = 300
MAX_ENTRY_CHARS = 60000
MAX_HISTORY = 200
MAX_UPLOAD = 10*1024*1024
POLL_INTERVAL = 0.4

SAFE_ENV = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8", "HOME": str(SANDBOX)}
PY_ENV = dict(SAFE_ENV, PYTHONUNBUFFERED="1", PYTHONDONTWRITEBYTECODE="1")
HELP_TEXT = "help | clear | history | pwd | cd | ls | cat | mkdir | touch | rm | edit | python"

def get_setting(n,d=""):
    try:
        if n in st.secrets:
            return str(st.secrets[n])
    except: pass
    return os.environ.get(n,d)

PASSWORD = get_setting("TERMINAL_PASSWORD")
ALLOW_PYTHON = get_setting("TERMINAL_ALLOW_PYTHON").lower() in ("1","true","yes","on")

def inside_sandbox(p):
    try:
        p.resolve().relative_to(SANDBOX)
        return True
    except: return False

def current_dir():
    p = (SANDBOX / st.session_state.cwd).resolve()
    return p if inside_sandbox(p) else SANDBOX

def rel_cwd():
    try:
        r = current_dir().relative_to(SANDBOX)
        return "~" if str(r)=="." else f"~/{r}"
    except: return "~"

def add_seg(e,t,txt):
    if not txt: return
    e["segs"].append([t,txt])

def nl(t):
    return t if t.endswith("\n") else t+"\n"

def _reader(stream,tag,q):
    fd = stream.fileno()
    while True:
        try:
            data = os.read(fd, 4096)
        except: break
        if not data: break
        try: q.put((tag, data.decode("utf-8","replace")))
        except: pass

class Proc:
    def __init__(self,popen,entry,label):
        self.popen=popen; self.entry=entry; self.label=label; self.q=queue.Queue()
        self.threads=[threading.Thread(target=_reader,args=(popen.stdout,"out",self.q),daemon=True),threading.Thread(target=_reader,args=(popen.stderr,"err",self.q),daemon=True)]
        for t in self.threads: t.start()
        self.timer=threading.Timer(MAX_RUNTIME, self.kill); self.timer.daemon=True; self.timer.start()
    def kill(self):
        try:
            if os.name=="posix": os.killpg(os.getpgid(self.popen.pid), signal.SIGKILL)
            else: self.popen.kill()
        except: pass
    def done(self): return not any(t.is_alive() for t in self.threads)

def start_process(argv,label,entry):
    try:
        popen=subprocess.Popen(argv,cwd=str(current_dir()),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=PY_ENV,bufsize=0,shell=False,start_new_session=True)
    except Exception as e:
        add_seg(entry,"err",str(e)); return
    st.session_state.proc=Proc(popen,entry,label)

def drain():
    proc=st.session_state.get("proc")
    if not proc: return "idle"
    while True:
        try: tag,text=proc.q.get_nowait()
        except: break
        add_seg(proc.entry,tag,text)
    if proc.popen.poll() is not None and proc.done():
        while True:
            try: tag,text=proc.q.get_nowait()
            except: break
            add_seg(proc.entry,tag,text)
        proc.timer.cancel()
        st.session_state.proc=None
        save_history()
        return "done"
    return "running"

def send_line(line):
    try:
        st.session_state.proc.popen.stdin.write((line+"\n").encode())
        st.session_state.proc.popen.stdin.flush()
    except: pass
    add_seg(st.session_state.proc.entry,"in",line+"\n")

def run_short(argv,entry):
    try:
        r=subprocess.run(argv,cwd=str(current_dir()),capture_output=True,timeout=TIMEOUT_SECONDS,env=SAFE_ENV,shell=False)
        add_seg(entry,"out",r.stdout.decode("utf-8","replace"))
        add_seg(entry,"err",r.stderr.decode("utf-8","replace"))
    except Exception as e: add_seg(entry,"err",str(e))

def execute(line,entry):
    line=line.strip()
    if not line: return False
    try: tokens=shlex.split(line)
    except: add_seg(entry,"err","sintaks salah"); return True
    cmd,args=tokens[0],tokens[1:]
    cwd=current_dir()
    if cmd=="help": add_seg(entry,"out",nl(HELP_TEXT))
    elif cmd=="clear": st.session_state.history=[]; return False
    elif cmd=="history": add_seg(entry,"out","\n".join(h["cmd"] for h in st.session_state.history))
    elif cmd=="pwd": add_seg(entry,"out",nl(rel_cwd()))
    elif cmd=="cd":
        t=args[0] if args else "~"
        new=SANDBOX if t=="~" else (cwd/t).resolve()
        if not inside_sandbox(new): add_seg(entry,"err","akses ditolak\n")
        elif not new.is_dir(): add_seg(entry,"err","bukan folder\n")
        else: st.session_state.cwd=str(new.relative_to(SANDBOX))
    elif cmd in ("ls","cat","head","tail","wc","mkdir","touch","rm","echo","whoami","date","uname","df","free","uptime"):
        if cmd=="mkdir":
            try: (cwd/args[0]).mkdir(parents=True,exist_ok=True)
            except Exception as e: add_seg(entry,"err",str(e))
        elif cmd=="touch":
            try: (cwd/args[0]).touch()
            except Exception as e: add_seg(entry,"err",str(e))
        elif cmd=="rm":
            try: (cwd/args[0]).unlink()
            except Exception as e: add_seg(entry,"err",str(e))
        else: run_short([cmd]+args,entry)
    elif cmd in ("python","python3"):
        if not ALLOW_PYTHON: add_seg(entry,"err","python nonaktif\n")
        else:
            if not args: start_process([sys.executable,"-u","-c","import code; code.interact()"],"python",entry)
            elif args[0]=="-c": start_process([sys.executable,"-u","-c",args[1]]+args[2:],"python -c",entry)
            else: start_process([sys.executable,"-u",str((cwd/args[0]).resolve())]+args[1:],f"python {args[0]}",entry)
    else: add_seg(entry,"err",f"{cmd}: tidak ditemukan\n")
    return True

def load_history():
    if PERSIST_HISTORY and HISTORY_FILE.exists():
        try: return json.loads(HISTORY_FILE.read_text())
        except: return []
    return []

def save_history():
    try: HISTORY_FILE.write_text(json.dumps(st.session_state.history[-200:],ensure_ascii=False))
    except: pass

for k,v in {"history":None,"cwd":".","proc":None,"authed":False,"editing":None,"edit_initial":"","edit_nonce":0,"up_nonce":0}.items():
    if k not in st.session_state: st.session_state[k]=v
if st.session_state.history is None: st.session_state.history=load_history()

css=""
css+="<style>\n"
css+=".stApp{background:#000}\n"
css+=".block-container{max-width:1100px;padding-top:24px}\n"
css+=".term-box{background:#000;border:1px solid #1f6f1f;border-radius:8px;height:50vh;overflow-y:auto;display:flex;flex-direction:column-reverse;padding:12px}\n"
css+=".term-inner{font-family:monospace;font-size:14px;color:#39ff14;white-space:pre-wrap}\n"
css+=".file-card{background:#0a0a0a;border:1px solid #1f6f1f;border-radius:6px;padding:8px;margin:4px}\n"
css+="</style>\n"
st.markdown(css,unsafe_allow_html=True)
st.markdown("### Web Terminal v2 - FILE MANAGER PRO - FIXED")

if PASSWORD and not st.session_state.authed:
    with st.form("login"):
        pw=st.text_input("Password",type="password")
        if st.form_submit_button("Masuk"):
            if hmac.compare_digest(pw.encode(),PASSWORD.encode()):
                st.session_state.authed=True; st.rerun()
            else: st.error("Salah")
    st.stop()

def terminal_html():
    parts=['<span>Terminal siap. Ketik help</span>\n']
    for h in st.session_state.history:
        parts.append(f'<span>{escape(h["cwd"])}$ {escape(h["cmd"])}</span>\n')
        for _,txt in h["segs"]: parts.append(escape(txt))
    return "".join(parts)

def terminal_view():
    if drain()=="done": st.rerun()
    st.markdown(f'<div class="term-box"><div class="term-inner">{terminal_html()}</div></div>',unsafe_allow_html=True)

st.fragment(terminal_view,run_every=POLL_INTERVAL if st.session_state.proc else None)()

with st.form("cmd_form",clear_on_submit=True):
    c1,c2=st.columns([8,1])
    txt=c1.text_input("cmd",label_visibility="collapsed",placeholder=f"{rel_cwd()}$")
    sub=c2.form_submit_button("Run")

if sub and txt.strip():
    if st.session_state.proc: send_line(txt); st.rerun()
    else:
        e={"cwd":rel_cwd(),"cmd":txt.strip(),"segs":[],"size":0}
        if execute(txt,e):
            st.session_state.history.append(e)
            st.session_state.history=st.session_state.history[-200:]
        save_history(); st.rerun()

# FILE MANAGER PRO
st.markdown("---")
st.markdown(f"#### 📁 File Manager - {rel_cwd()}")
col_up, col_ref = st.columns([3,1])
with col_up:
    ups=st.file_uploader("Upload file (max 10MB)",accept_multiple_files=True,key=f"up_{st.session_state.up_nonce}")
    if ups:
        for f in ups:
            if f.size>MAX_UPLOAD: st.error(f"{f.name} terlalu besar")
            else:
                (current_dir()/Path(f.name).name).write_bytes(f.getvalue())
                st.toast(f"{f.name} terupload")
        st.session_state.up_nonce+=1
        st.rerun()

with col_ref:
    if st.button("🔄 Refresh"):
        st.rerun()

# List file dengan download
files = list(current_dir().iterdir())
if not files:
    st.caption("Folder kosong")
else:
    for p in sorted(files):
        is_dir = p.is_dir()
        icon = "📁" if is_dir else "📄"
        c1,c2,c3,c4 = st.columns([4,1,1,1])
        c1.markdown(f"{icon} **{p.name}** {'(folder)' if is_dir else f'({p.stat().st_size} bytes)'}")
        if not is_dir:
            try:
                data = p.read_bytes()
                c2.download_button("⬇️ Download", data=data, file_name=p.name, key=f"dl_{p.name}")
            except Exception as e:
                c2.caption("gagal")
            if c3.button("🗑️", key=f"del_{p.name}"):
                try:
                    p.unlink()
                    st.toast(f"{p.name} dihapus")
                    st.rerun()
                except Exception as e: st.error(str(e))
        else:
            if c2.button("📂 Buka", key=f"open_{p.name}"):
                st.session_state.cwd = str(p.relative_to(SANDBOX))
                st.rerun()
            if c3.button("🗑️", key=f"rmdir_{p.name}"):
                try:
                    p.rmdir()
                    st.rerun()
                except: st.error("Folder tidak kosong")

if st.button("🧹 Clear History"):
    st.session_state.history=[]
    save_history()
    st.rerun()
