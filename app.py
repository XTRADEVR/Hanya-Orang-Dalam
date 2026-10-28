"""
Web Terminal v2 FIXED FINAL
"""

import codecs
import hmac
import json
import os
import queue
import re
import shlex
import signal
import subprocess
import sys
import threading
import time
from html import escape
from pathlib import Path
import streamlit as st

st.set_page_config(page_title="Web Terminal", page_icon="💻", layout="wide")
BASE_DIR = Path(__file__).resolve().parent
SANDBOX = BASE_DIR / "sandbox"
SANDBOX.mkdir(exist_ok=True)
HISTORY_FILE = BASE_DIR / "terminal_history.json"
PERSIST_HISTORY = True
TIMEOUT_SECONDS = 10
MAX_RUNTIME = 300
MEM_LIMIT = 1024*1024*1024
FSIZE_LIMIT = 20*1024*1024
MAX_ENTRY_CHARS = 60000
MAX_HISTORY = 200
MAX_UPLOAD = 5*1024*1024
MAX_EDIT_BYTES = 200*1024
POLL_INTERVAL = 0.4
PATH_COMMANDS = {"ls", "cat", "head", "tail", "wc"}
PLAIN_COMMANDS = {"echo", "whoami", "date", "uname", "df", "free", "uptime"}
BLOCKED_WORDS = {"sudo", "su", "mkfs", "dd", "chmod", "chown", "kill", "killall", "shutdown", "reboot", "halt", "curl", "wget", "nc", "ncat", "bash", "sh", "zsh", "ssh", "scp", "mv", "cp", "mount", "umount", "fdisk", "crontab"}
FORBIDDEN_CHARS = set(";&|<>`$\n\r")
FORK_BOMB_RE = re.compile(r":\s*\(\s*\)\s*\{")
PKG_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")
SAFE_ENV = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8", "HOME": str(SANDBOX)}
PY_ENV = dict(SAFE_ENV, PYTHONUNBUFFERED="1", PYTHONDONTWRITEBYTECODE="1")
INTERACT_CODE = "import code,sys\nprint('Python '+sys.version.split()[0]+' interaktif.', flush=True)\ncode.interact(banner='', exitmsg='')"
HELP_TEXT = """help | clear | history | pwd | cd | ls | cat | mkdir | touch | rm | edit | python"""

def get_setting(name, default=""):
    try:
        if name in st.secrets:
            return str(st.secrets[name])
    except Exception:
        pass
    return os.environ.get(name, default)

PASSWORD = get_setting("TERMINAL_PASSWORD")
ALLOW_PYTHON = get_setting("TERMINAL_ALLOW_PYTHON").lower() in ("1", "true", "yes", "on")

def inside_sandbox(path):
    try:
        path.resolve().relative_to(SANDBOX)
        return True
    except ValueError:
        return False

def current_dir():
    p = (SANDBOX / st.session_state.cwd).resolve()
    return p if inside_sandbox(p) else SANDBOX

def rel_cwd():
    try:
        r = current_dir().relative_to(SANDBOX)
        return "~" if str(r) == "." else f"~/{r}"
    except ValueError:
        return "~"

def validate_path_args(args):
    cwd = current_dir()
    for a in args:
        if a.startswith("-"):
            return f"opsi tidak diizinkan: {a}"
        if not inside_sandbox(cwd / a):
            return f"akses ditolak: {a}"
    return None

def nl(text):
    return text if (not text or text.endswith("\n")) else text + "\n"

def add_seg(entry, tag, text):
    if not text:
        return
    entry["segs"].append([tag, text])

def _limits():
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (MAX_RUNTIME, MAX_RUNTIME))
        resource.setrlimit(resource.RLIMIT_AS, (MEM_LIMIT, MEM_LIMIT))
    except Exception:
        pass

def _reader(stream, tag, q):
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    fd = stream.fileno()
    while True:
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        text = decoder.decode(data)
        if text:
            q.put((tag, text))

class Proc:
    def __init__(self, popen, entry, label):
        self.popen = popen
        self.entry = entry
        self.label = label
        self.q = queue.Queue()
        self.killed_reason = None
        self.threads = [threading.Thread(target=_reader, args=(popen.stdout, "out", self.q), daemon=True), threading.Thread(target=_reader, args=(popen.stderr, "err", self.q), daemon=True)]
        for t in self.threads:
            t.start()
        self.timer = threading.Timer(MAX_RUNTIME, self.kill, args=(f"timeout {MAX_RUNTIME}",))
        self.timer.daemon = True
        self.timer.start()
    def kill(self, reason):
        if self.popen.poll() is None:
            self.killed_reason = reason
            try:
                import os as _os, signal as _sig
                _os.killpg(_os.getpgid(self.popen.pid), _sig.SIGKILL)
            except Exception:
                pass
    def threads_done(self):
        return not any(t.is_alive() for t in self.threads)

def start_process(argv, label, entry):
    kwargs = {}
    if os.name == "posix":
        kwargs["start_new_session"] = True
        kwargs["preexec_fn"] = _limits
    try:
        popen = subprocess.Popen(argv, cwd=str(current_dir()), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=PY_ENV, bufsize=0, shell=False, **kwargs)
    except Exception as e:
        add_seg(entry, "err", f"gagal: {e}\n")
        return
    st.session_state.proc = Proc(popen, entry, label)

def drain():
    proc = st.session_state.get("proc")
    if not proc:
        return "idle"
    def pull():
        while True:
            try:
                tag, text = proc.q.get_nowait()
            except queue.Empty:
                break
            add_seg(proc.entry, tag, text)
    pull()
    if proc.popen.poll() is not None and proc.threads_done():
        pull()
        proc.timer.cancel()
        st.session_state.proc = None
        save_history()
        return "done"
    return "running"

def send_line(line):
    proc = st.session_state.proc
    try:
        proc.popen.stdin.write((line + "\n").encode("utf-8"))
        proc.popen.stdin.flush()
    except Exception:
        pass
    add_seg(proc.entry, "in", line + "\n")

def run_short(argv, entry):
    try:
        r = subprocess.run(argv, cwd=str(current_dir()), capture_output=True, timeout=TIMEOUT_SECONDS, env=SAFE_ENV, shell=False)
        add_seg(entry, "out", r.stdout.decode("utf-8", "replace"))
        add_seg(entry, "err", r.stderr.decode("utf-8", "replace"))
    except Exception as e:
        add_seg(entry, "err", str(e))

def out(entry, text):
    add_seg(entry, "out", nl(text))

def err(entry, text):
    add_seg(entry, "err", nl(text))

def execute(line, entry):
    line = line.strip()
    if not line:
        return False
    try:
        tokens = shlex.split(line)
    except Exception as e:
        err(entry, str(e))
        return True
    cmd, args = tokens[0], tokens[1:]
    if cmd == "help":
        out(entry, HELP_TEXT)
    elif cmd == "clear":
        st.session_state.history = []
        return False
    elif cmd == "pwd":
        out(entry, rel_cwd())
    elif cmd == "cd":
        target = args[0] if args else "~"
        new = SANDBOX if target == "~" else (current_dir() / target).resolve()
        if not inside_sandbox(new):
            err(entry, "akses ditolak")
        elif not new.is_dir():
            err(entry, "bukan folder")
        else:
            st.session_state.cwd = str(new.relative_to(SANDBOX))
    elif cmd in PATH_COMMANDS or cmd in PLAIN_COMMANDS:
        run_short([cmd] + args, entry)
    elif cmd == "python":
        run_short([sys.executable, "--version"], entry)
    else:
        err(entry, f"{cmd}: tidak diizinkan")
    return True

def load_history():
    if PERSIST_HISTORY and HISTORY_FILE.exists():
        try:
            return json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return []

def save_history():
    try:
        HISTORY_FILE.write_text(json.dumps(st.session_state.history[-200:], ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass

for k, v in {"history": None, "cwd": ".", "prev_cwd": ".", "proc": None, "authed": False, "editing": None, "edit_initial": "", "edit_nonce": 0, "up_nonce": 0, "flash": ""}.items():
    if k not in st.session_state:
        st.session_state[k] = v
if st.session_state.history is None:
    st.session_state.history = load_history()

# CSS TANPA TRIPLE QUOTE - AMAN
css_code = "<style>\n"
css_code += ".stApp { background: #000; }\n"
css_code += ".block-container { max-width: 1100px; padding-top: 24px; }\n"
css_code += ".term-box { background: #000; border: 1px solid #1f6f1f; border-radius: 8px; height: 62vh; overflow-y: auto; display: flex; flex-direction: column-reverse; padding: 12px; }\n"
css_code += ".term-inner { font-family: monospace; font-size: 14px; color: #39ff14; }\n"
css_code += "</style>"

st.markdown(css_code, unsafe_allow_html=True)
st.markdown("### Web Terminal v2 - FIXED FINAL")

if PASSWORD and not st.session_state.authed:
    with st.form("login"):
        pw = st.text_input("Password", type="password")
        if st.form_submit_button("Masuk"):
            if hmac.compare_digest(pw.encode(), PASSWORD.encode()):
                st.session_state.authed = True
                st.rerun()
            else:
                st.error("Salah")
    st.stop()

def terminal_html():
    parts = ['<span>Terminal siap</span>\n']
    for h in st.session_state.history:
        parts.append(f'<span>{escape(h["cwd"])}$ {escape(h["cmd"])}</span>\n')
        for tag, text in h["segs"]:
            parts.append(f'<span>{escape(text)}</span>')
    return "".join(parts)

def terminal_view():
    if drain() == "done":
        st.rerun()
    st.markdown(f'<div class="term-box"><div class="term-inner">{terminal_html()}</div></div>', unsafe_allow_html=True)

st.fragment(terminal_view, run_every=POLL_INTERVAL if st.session_state.proc else None)()

with st.form("cmd_form", clear_on_submit=True):
    c1, c2 = st.columns([8, 1])
    text = c1.text_input("cmd", label_visibility="collapsed", placeholder=f"{rel_cwd()}$")
    submitted = c2.form_submit_button("Run")

if submitted and text.strip():
    if st.session_state.proc:
        send_line(text)
        st.rerun()
    else:
        entry = {"cwd": rel_cwd(), "cmd": text.strip(), "segs": [], "size": 0}
        if execute(text, entry):
            st.session_state.history.append(entry)
        save_history()
        st.rerun()
