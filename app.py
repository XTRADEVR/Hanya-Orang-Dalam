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

st.set_page_config(page_title="Web Terminal v2 FULL", page_icon="💻", layout="wide")
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
INTERACT_CODE = "import code,sys\nprint('Python '+sys.version.split()[0]+' interaktif. Ketik exit() untuk keluar.', flush=True)\ncode.interact(banner='', exitmsg='')"
HELP_TEXT = '''Perintah:
  help | clear | history
  pwd | cd | ls | cat | head | tail | wc | mkdir | touch | rm | edit | echo
  whoami | date | uname | df | free | uptime
  pip list | freeze | --version | show <paket>
  python --version | python <skrip> | python -c "kode"
'''

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
            if "/" in a or ".." in a or "=" in a:
                return f"opsi tidak diizinkan: {a}"
            continue
        if not inside_sandbox(cwd / a):
            return f"akses ditolak: {a}"
    return None

def nl(text):
    return text if (not text or text.endswith("\n")) else text + "\n"

def add_seg(entry, tag, text):
    if not text:
        return
    size = entry.get("size", 0)
    if size >= MAX_ENTRY_CHARS:
        return
    size += len(text)
    entry["size"] = size
    if size > MAX_ENTRY_CHARS:
        over = size - MAX_ENTRY_CHARS
        text = text[: len(text) - over] + "\n[... output dipotong ...]\n"
    segs = entry["segs"]
    if segs and segs[-1][0] == tag:
        segs[-1][1] += text
    else:
        segs.append([tag, text])

def _limits():
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (MAX_RUNTIME, MAX_RUNTIME))
        resource.setrlimit(resource.RLIMIT_AS, (MEM_LIMIT, MEM_LIMIT))
        resource.setrlimit(resource.RLIMIT_FSIZE, (FSIZE_LIMIT, FSIZE_LIMIT))
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
        self.started = time.time()
        self.killed_reason = None
        self.threads = [
            threading.Thread(target=_reader, args=(popen.stdout, "out", self.q), daemon=True),
            threading.Thread(target=_reader, args=(popen.stderr, "err", self.q), daemon=True),
        ]
        for t in self.threads:
            t.start()
        self.timer = threading.Timer(MAX_RUNTIME, self.kill, args=(f"melewati batas waktu {MAX_RUNTIME} detik",))
        self.timer.daemon = True
        self.timer.start()
    def kill(self, reason):
        if self.popen.poll() is None:
            self.killed_reason = reason
            try:
                if os.name == "posix":
                    os.killpg(os.getpgid(self.popen.pid), signal.SIGKILL)
                else:
                    self.popen.kill()
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
        add_seg(entry, "err", f"gagal memulai proses: {e}\n")
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
        code = proc.popen.returncode
        entry = proc.entry
        if entry["segs"] and not entry["segs"][-1][1].endswith("\n"):
            add_seg(entry, "out", "\n")
        if proc.killed_reason:
            add_seg(entry, "err", f"[dihentikan: {proc.killed_reason}]\n")
        elif code not in (0, None):
            add_seg(entry, "err", f"[proses berakhir dengan kode {code}]\n")
        try:
            proc.popen.stdin.close()
        except Exception:
            pass
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
        so = r.stdout.decode("utf-8", "replace")
        se = r.stderr.decode("utf-8", "replace")
        add_seg(entry, "out", nl(so))
        add_seg(entry, "err", nl(se))
    except Exception as e:
        add_seg(entry, "err", f"[error] {e}\n")

def out(entry, text):
    add_seg(entry, "out", nl(text))

def err(entry, text):
    add_seg(entry, "err", nl(text))

def execute(line, entry):
    line = line.strip()
    if not line:
        return False
    if "\n" in line or "\r" in line:
        err(entry, "diblokir: baris baru tidak diizinkan")
        return True
    try:
        tokens = shlex.split(line)
    except ValueError as e:
        err(entry, f"sintaks salah: {e}")
        return True
    if not tokens:
        return False
    cmd, args = tokens[0], tokens[1:]
    is_py = cmd in ("python", "python3")
    if not is_py:
        if FORK_BOMB_RE.search(line):
            err(entry, "diblokir: fork bomb")
            return True
        if any(ch in FORBIDDEN_CHARS for ch in line):
            err(entry, "diblokir: karakter ; & | < > ` $ tidak diizinkan")
            return True
    if cmd in BLOCKED_WORDS:
        err(entry, f"diblokir: {cmd}")
        return True
    cwd = current_dir()
    if cmd == "help":
        out(entry, HELP_TEXT)
    elif cmd == "clear":
        st.session_state.history = []
        return False
    elif cmd == "history":
        out(entry, "\n".join(f"{i+1:>4}  {h['cmd']}" for i, h in enumerate(st.session_state.history)))
    elif cmd == "pwd":
        out(entry, rel_cwd())
    elif cmd == "cd":
        if len(args) > 1:
            err(entry, "cd: terlalu banyak argumen")
            return True
        target = args[0] if args else "~"
        if target == "-":
            new = (SANDBOX / st.session_state.prev_cwd).resolve()
        elif target in ("~", ""):
            new = SANDBOX
        else:
            new = (cwd / target).resolve()
        if not inside_sandbox(new):
            err(entry, "cd: akses ditolak")
        elif not new.is_dir():
            err(entry, f"cd: {target}: bukan folder")
        else:
            st.session_state.prev_cwd = st.session_state.cwd
            st.session_state.cwd = str(new.relative_to(SANDBOX))
    elif cmd == "mkdir":
        parents = "-p" in args
        names = [a for a in args if a != "-p"]
        for n in names:
            p = cwd / n
            if not inside_sandbox(p):
                err(entry, f"akses ditolak: {n}")
                continue
            try:
                p.mkdir(parents=parents, exist_ok=parents)
            except Exception as e:
                err(entry, f"mkdir: {n}: {e}")
    elif cmd == "touch":
        for n in args:
            p = cwd / n
            if not inside_sandbox(p):
                err(entry, f"tidak diizinkan: {n}")
                continue
            try:
                p.touch()
            except Exception as e:
                err(entry, f"touch: {n}: {e}")
    elif cmd == "rm":
        for n in args:
            p = cwd / n
            if not p.is_file():
                err(entry, f"rm: {n}: bukan file")
            else:
                try:
                    p.unlink()
                except Exception as e:
                    err(entry, f"rm: {n}: {e}")
    elif cmd == "edit":
        p = cwd / args[0]
        text = p.read_text(encoding="utf-8") if p.exists() else ""
        st.session_state.editing = str(p.relative_to(SANDBOX))
        st.session_state.edit_initial = text
        st.session_state.edit_nonce += 1
        out(entry, f"editor dibuka untuk {args[0]}")
    elif is_py:
        if args in (["--version"], ["-V"]):
            run_short([sys.executable, "--version"], entry)
        elif not ALLOW_PYTHON:
            err(entry, "python: dinonaktifkan")
        elif not args:
            start_process([sys.executable, "-u", "-c", INTERACT_CODE], "python", entry)
        elif args[0] == "-c":
            start_process([sys.executable, "-u", "-c", args[1]] + args[2:], "python -c", entry)
        else:
            script = (cwd / args[0]).resolve()
            start_process([sys.executable, "-u", str(script)] + args[1:], f"python {args[0]}", entry)
    elif cmd == "pip":
        pip = [sys.executable, "-m", "pip", "--disable-pip-version-check"]
        run_short(pip + args, entry)
    elif cmd in PATH_COMMANDS or cmd in PLAIN_COMMANDS:
        run_short([cmd] + args, entry)
    else:
        err(entry, f"{cmd}: tidak ditemukan")
    return True

def load_history():
    if PERSIST_HISTORY and HISTORY_FILE.exists():
        try:
            data = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
            return data[-MAX_HISTORY:]
        except Exception:
            pass
    return []

def save_history():
    try:
        HISTORY_FILE.write_text(json.dumps(st.session_state.history[-MAX_HISTORY:], ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass

defaults = {"history": None, "cwd": ".", "prev_cwd": ".", "proc": None, "authed": False, "editing": None, "edit_initial": "", "edit_nonce": 0, "up_nonce": 0, "flash": ""}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v
if st.session_state.history is None:
    st.session_state.history = load_history()

# CSS FINAL TANPA 1.5rem
css_code = ""
css_code += "<style>\n"
css_code += ".stApp { background: #000; }\n"
css_code += ".block-container { max-width: 1100px; padding-top: 24px; }\n"
css_code += ".term-box { background: #000; border: 1px solid #1f6f1f; border-radius: 8px; height: 62vh; overflow-y: auto; display: flex; flex-direction: column-reverse; padding: 12px; }\n"
css_code += ".term-inner { font-family: monospace; font-size: 14px; color: #39ff14; }\n"
css_code += ".term-inner .prompt { color: #7dffb0; font-weight: 600; }\n"
css_code += ".term-inner .cmd { color: #ffffff; }\n"
css_code += ".term-inner .out { color: #e8ffe8; }\n"
css_code += ".term-inner .err { color: #ff4d4d; }\n"
css_code += ".term-inner .stdin { color: #6ee7ff; }\n"
css_code += ".term-inner .muted { color: #5fae5f; }\n"
css_code += "</style>"

st.markdown(css_code, unsafe_allow_html=True)
st.markdown("### Web Terminal v2 - FULL FIXED")

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
    proc = st.session_state.proc
    parts = ['<span class="muted">Web Terminal siap. Ketik help</span>\n']
    for h in st.session_state.history:
        parts.append(f'<span class="prompt">{escape(h["cwd"])}$</span> <span class="cmd">{escape(h["cmd"])}</span>\n')
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
            st.session_state.history = st.session_state.history[-MAX_HISTORY:]
        save_history()
        st.rerun()

if st.session_state.editing:
    rel = st.session_state.editing
    with st.container(border=True):
        st.markdown(f"**Editor:** `{rel}`")
        content = st.text_area("isi file", value=st.session_state.edit_initial, height=300, key=f"editor_{st.session_state.edit_nonce}", label_visibility="collapsed")
        b1, b2, _ = st.columns([1, 1, 5])
        if b1.button("Simpan"):
            target = SANDBOX / rel
            target.write_text(content, encoding="utf-8")
            st.session_state.flash = f"{rel} tersimpan"
            st.rerun()
        if b2.button("Tutup"):
            st.session_state.editing = None
            st.rerun()

with st.expander("Upload file"):
    ups = st.file_uploader("Pilih file", accept_multiple_files=True, key=f"uploader_{st.session_state.up_nonce}")
    if ups:
        for f in ups:
            target = current_dir() / Path(f.name).name
            target.write_bytes(f.getvalue())
        st.rerun()
