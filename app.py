Web Terminal v2 (Streamlit)

Fitur:
- Perintah aman (allowlist) + sandbox folder ./sandbox
- Working directory persisten (cd), tersimpan di st.session_state
- Eksekusi skrip Python & interpreter interaktif dengan streaming output
  dan input (stdin) langsung dari terminal  -> DIMATIKAN secara default
- stderr tampil merah, input pengguna tampil biru muda
- Auto-scroll ke baris terbaru, font Fira Code, latar hitam pekat
- Editor file (perintah `edit`) dan upload file ke folder aktif
- Riwayat disimpan ke file agar bertahan setelah browser di-refresh

KEAMANAN - BACA INI:
Perintah biasa (ls, cat, ...) dikunci ke sandbox dan allowlist.
Eksekusi Python (python script.py / python / python -c) TIDAK bisa
dikunci sepenuhnya dari dalam Python: skrip bisa `import os` dan menyentuh
apa pun yang boleh diakses user server. Batas yang dipasang di sini
(timeout, batas CPU/RAM/ukuran file, env minimal, password) hanya
mengurangi risiko, bukan isolasi. Aktifkan hanya untuk pemakaian pribadi
atau di dalam container, dengan TERMINAL_PASSWORD terisi:

    TERMINAL_ALLOW_PYTHON=1   (environment atau st.secrets)
    TERMINAL_PASSWORD=...     (environment atau st.secrets)
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

# ---------------------------------------------------------------------------
# Konfigurasi
# ---------------------------------------------------------------------------
st.set_page_config(page_title="Web Terminal", page_icon="💻", layout="wide")

BASE_DIR = Path(__file__).resolve().parent
SANDBOX = BASE_DIR / "sandbox"
SANDBOX.mkdir(exist_ok=True)

HISTORY_FILE = BASE_DIR / "terminal_history.json"
PERSIST_HISTORY = True          # simpan riwayat ke file (bertahan setelah refresh)
TIMEOUT_SECONDS = 10            # batas waktu perintah singkat (ls, pip list, ...)
MAX_RUNTIME = 300               # batas total proses Python interaktif (detik)
MEM_LIMIT = 1024 * 1024 * 1024  # batas memori proses Python (1 GB, Linux)
FSIZE_LIMIT = 20 * 1024 * 1024  # batas ukuran file yang ditulis proses (20 MB)
MAX_ENTRY_CHARS = 60_000        # batas output per perintah
MAX_HISTORY = 200
MAX_UPLOAD = 5 * 1024 * 1024
MAX_EDIT_BYTES = 200 * 1024
POLL_INTERVAL = 0.4             # detik, refresh live output

PATH_COMMANDS = {"ls", "cat", "head", "tail", "wc"}
PLAIN_COMMANDS = {"echo", "whoami", "date", "uname", "df", "free", "uptime"}

BLOCKED_WORDS = {
    "sudo", "su", "mkfs", "dd", "chmod", "chown", "kill", "killall",
    "shutdown", "reboot", "halt", "curl", "wget", "nc", "ncat", "bash", "sh",
    "zsh", "ssh", "scp", "mv", "cp", "mount", "umount", "fdisk", "crontab",
}
FORBIDDEN_CHARS = set(";&|<>`$\n\r")
FORK_BOMB_RE = re.compile(r":\s*\(\s*\)\s*\{")
PKG_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")

SAFE_ENV = {
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "LANG": "C.UTF-8",
    "HOME": str(SANDBOX),
}
PY_ENV = dict(SAFE_ENV, PYTHONUNBUFFERED="1", PYTHONDONTWRITEBYTECODE="1")

INTERACT_CODE = (
    "import code,sys\n"
    "print('Python '+sys.version.split()[0]+' interaktif. "
    "Ketik exit() atau klik Stop untuk keluar.', flush=True)\n"
    "code.interact(banner='', exitmsg='')"
)

HELP_TEXT = """Perintah yang tersedia:
  help | clear | history
  pwd                    folder aktif (relatif terhadap sandbox)
  cd [folder|~|-]        pindah folder (hanya di dalam sandbox)
  ls [-la] [path]        daftar file
  cat|head|tail|wc <file>
  mkdir [-p] <folder>    buat folder
  touch <file>           buat file kosong
  rm <file>              hapus file (bukan folder)
  edit <file>            buka editor teks di bawah terminal
  echo <teks>
  whoami | date | uname [-a] | df [-h] | free [-h] | uptime
  pip list | freeze | --version | show <paket>
  python --version

Python (hanya jika TERMINAL_ALLOW_PYTHON=1):
  python <skrip.py> [arg]   jalankan skrip, output tampil langsung,
                            input() membaca dari kotak input di bawah
  python                    interpreter interaktif (baris kosong
                            menutup blok for/if/def; exit() untuk keluar)
  python -c "kode"          jalankan kode satu baris
  Tombol Stop = Ctrl+C

Pipe, redirect, ; && $() dan perintah berbahaya diblokir.
Aplikasi yang butuh TTY penuh (vim, top, nano) tidak didukung."""


def get_setting(name: str, default: str = "") -> str:
    try:
        if name in st.secrets:
            return str(st.secrets[name])
    except Exception:  # noqa: BLE001
        pass
    return os.environ.get(name, default)


PASSWORD = get_setting("TERMINAL_PASSWORD")
ALLOW_PYTHON = get_setting("TERMINAL_ALLOW_PYTHON").lower() in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------------
# Keamanan path & utilitas
# ---------------------------------------------------------------------------
def inside_sandbox(path: Path) -> bool:
    try:
        path.resolve().relative_to(SANDBOX)
        return True
    except ValueError:
        return False


def current_dir() -> Path:
    p = (SANDBOX / st.session_state.cwd).resolve()
    return p if inside_sandbox(p) else SANDBOX


def rel_cwd() -> str:
    try:
        r = current_dir().relative_to(SANDBOX)
        return "~" if str(r) == "." else f"~/{r}"
    except ValueError:
        return "~"


def validate_path_args(args: list) -> "str | None":
    cwd = current_dir()
    for a in args:
        if a.startswith("-"):
            if "/" in a or ".." in a or "=" in a:
                return f"opsi tidak diizinkan: {a}"
            continue
        if not inside_sandbox(cwd / a):
            return f"akses ditolak (di luar sandbox): {a}"
    return None


def nl(text: str) -> str:
    return text if (not text or text.endswith("\n")) else text + "\n"


def add_seg(entry: dict, tag: str, text: str) -> None:
    """Tambah potongan output ke entry. tag: out | err | in"""
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


# ---------------------------------------------------------------------------
# Proses panjang / interaktif (streaming)
# ---------------------------------------------------------------------------
def _limits() -> None:  # dijalankan di proses anak (Linux/macOS)
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (MAX_RUNTIME, MAX_RUNTIME))
        resource.setrlimit(resource.RLIMIT_AS, (MEM_LIMIT, MEM_LIMIT))
        resource.setrlimit(resource.RLIMIT_FSIZE, (FSIZE_LIMIT, FSIZE_LIMIT))
    except Exception:  # noqa: BLE001
        pass


def _reader(stream, tag: str, q: "queue.Queue") -> None:
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
    def __init__(self, popen: subprocess.Popen, entry: dict, label: str):
        self.popen = popen
        self.entry = entry
        self.label = label
        self.q: "queue.Queue" = queue.Queue()
        self.started = time.time()
        self.killed_reason = None
        self.threads = [
            threading.Thread(target=_reader, args=(popen.stdout, "out", self.q), daemon=True),
            threading.Thread(target=_reader, args=(popen.stderr, "err", self.q), daemon=True),
        ]
        for t in self.threads:
            t.start()
        # penjaga: proses pasti mati setelah MAX_RUNTIME walau tab ditutup
        self.timer = threading.Timer(
            MAX_RUNTIME, self.kill, args=(f"melewati batas waktu {MAX_RUNTIME} detik",)
        )
        self.timer.daemon = True
        self.timer.start()

    def kill(self, reason: str) -> None:
        if self.popen.poll() is None:
            self.killed_reason = reason
            try:
                if os.name == "posix":
                    os.killpg(os.getpgid(self.popen.pid), signal.SIGKILL)
                else:
                    self.popen.kill()
            except Exception:  # noqa: BLE001
                pass

    def threads_done(self) -> bool:
        return not any(t.is_alive() for t in self.threads)


def start_process(argv: list, label: str, entry: dict) -> None:
    kwargs = {}
    if os.name == "posix":
        kwargs["start_new_session"] = True
        kwargs["preexec_fn"] = _limits
    try:
        popen = subprocess.Popen(
            argv,
            cwd=str(current_dir()),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=PY_ENV,
            bufsize=0,
            shell=False,
            **kwargs,
        )
    except Exception as e:  # noqa: BLE001
        add_seg(entry, "err", f"gagal memulai proses: {e}\n")
        return
    st.session_state.proc = Proc(popen, entry, label)


def drain() -> str:
    """Tarik output baru dari proses aktif ke riwayat. Return 'done' jika selesai."""
    proc = st.session_state.get("proc")
    if not proc:
        return "idle"

    def pull() -> None:
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
        except Exception:  # noqa: BLE001
            pass
        st.session_state.proc = None
        save_history()
        return "done"
    return "running"


def send_line(line: str) -> None:
    proc = st.session_state.proc
    try:
        proc.popen.stdin.write((line + "\n").encode("utf-8"))
        proc.popen.stdin.flush()
    except (BrokenPipeError, OSError, ValueError):
        pass
    add_seg(proc.entry, "in", line + "\n")


# ---------------------------------------------------------------------------
# Perintah singkat
# ---------------------------------------------------------------------------
def run_short(argv: list, entry: dict) -> None:
    try:
        r = subprocess.run(
            argv,
            cwd=str(current_dir()),
            capture_output=True,
            timeout=TIMEOUT_SECONDS,
            env=SAFE_ENV,
            shell=False,
        )
        so = r.stdout.decode("utf-8", "replace")
        se = r.stderr.decode("utf-8", "replace")
        add_seg(entry, "out", nl(so))
        add_seg(entry, "err", nl(se))
        if r.returncode != 0 and not se:
            add_seg(entry, "err", f"[exit {r.returncode}]\n")
    except subprocess.TimeoutExpired:
        add_seg(entry, "err", f"[timeout] dihentikan setelah {TIMEOUT_SECONDS} detik\n")
    except FileNotFoundError:
        add_seg(entry, "err", f"{argv[0]}: perintah tidak tersedia di server ini\n")
    except Exception as e:  # noqa: BLE001
        add_seg(entry, "err", f"[error] {e}\n")


def out(entry: dict, text: str) -> None:
    add_seg(entry, "out", nl(text))


def err(entry: dict, text: str) -> None:
    add_seg(entry, "err", nl(text))


def execute(line: str, entry: dict) -> bool:
    """Jalankan satu baris. Return False jika entry tidak perlu dicatat (mis. clear)."""
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
            err(entry, "diblokir: pola fork bomb terdeteksi")
            return True
        if any(ch in FORBIDDEN_CHARS for ch in line):
            err(entry, "diblokir: karakter ; & | < > ` $ tidak diizinkan")
            return True
    if cmd in BLOCKED_WORDS:
        err(entry, f"diblokir: perintah '{cmd}' tidak diizinkan di terminal ini")
        return True

    cwd = current_dir()

    # ---- builtin ----
    if cmd == "help":
        out(entry, HELP_TEXT)
    elif cmd == "clear":
        st.session_state.history = []
        return False
    elif cmd == "history":
        out(entry, "\n".join(f"{i + 1:>4}  {h['cmd']}" for i, h in enumerate(st.session_state.history)))
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
            err(entry, "cd: akses ditolak (di luar sandbox)")
        elif not new.is_dir():
            err(entry, f"cd: {target}: bukan folder")
        else:
            st.session_state.prev_cwd = st.session_state.cwd
            st.session_state.cwd = str(new.relative_to(SANDBOX))
    elif cmd == "mkdir":
        parents = "-p" in args
        names = [a for a in args if a != "-p"]
        if not names:
            err(entry, "mkdir: nama folder kosong")
        for n in names:
            if n.startswith("-"):
                err(entry, f"mkdir: opsi tidak diizinkan: {n}")
                continue
            p = cwd / n
            if not inside_sandbox(p):
                err(entry, f"mkdir: akses ditolak (di luar sandbox): {n}")
                continue
            try:
                p.mkdir(parents=parents, exist_ok=parents)
            except Exception as e:  # noqa: BLE001
                err(entry, f"mkdir: {n}: {e}")
    elif cmd == "touch":
        if not args:
            err(entry, "touch: nama file kosong")
        for n in args:
            p = cwd / n
            if n.startswith("-") or not inside_sandbox(p):
                err(entry, f"touch: tidak diizinkan: {n}")
                continue
            try:
                p.touch()
            except Exception as e:  # noqa: BLE001
                err(entry, f"touch: {n}: {e}")
    elif cmd == "rm":
        if not args:
            err(entry, "rm: nama file kosong")
        for n in args:
            p = cwd / n
            if n.startswith("-"):
                err(entry, f"rm: opsi tidak diizinkan: {n} (hanya file, tanpa -r/-f)")
            elif not inside_sandbox(p):
                err(entry, f"rm: akses ditolak (di luar sandbox): {n}")
            elif not p.is_file():
                err(entry, f"rm: {n}: bukan file / tidak ada")
            else:
                try:
                    p.unlink()
                except Exception as e:  # noqa: BLE001
                    err(entry, f"rm: {n}: {e}")
    elif cmd == "edit":
        if len(args) != 1 or args[0].startswith("-"):
            err(entry, "pemakaian: edit <file>")
        else:
            p = cwd / args[0]
            if not inside_sandbox(p) or p.is_dir():
                err(entry, "edit: path tidak diizinkan")
            else:
                try:
                    if p.exists() and p.stat().st_size > MAX_EDIT_BYTES:
                        err(entry, "edit: file terlalu besar")
                    else:
                        text = p.read_text(encoding="utf-8") if p.exists() else ""
                        st.session_state.editing = str(p.relative_to(SANDBOX))
                        st.session_state.edit_initial = text
                        st.session_state.edit_nonce += 1
                        out(entry, f"editor dibuka untuk {args[0]} (lihat panel di bawah terminal)")
                except UnicodeDecodeError:
                    err(entry, "edit: file bukan teks UTF-8")
                except Exception as e:  # noqa: BLE001
                    err(entry, f"edit: {e}")

    # ---- python ----
    elif is_py:
        if args in (["--version"], ["-V"]):
            run_short([sys.executable, "--version"], entry)
        elif not ALLOW_PYTHON:
            err(
                entry,
                "python: eksekusi skrip dinonaktifkan. Aktifkan dengan TERMINAL_ALLOW_PYTHON=1 "
                "(environment atau st.secrets) dan isi TERMINAL_PASSWORD. Hanya 'python --version' yang tersedia.",
            )
        elif not args:
            start_process([sys.executable, "-u", "-c", INTERACT_CODE], "python (interaktif)", entry)
        elif args[0] == "-c":
            if len(args) < 2:
                err(entry, "python: -c membutuhkan kode")
            else:
                start_process([sys.executable, "-u", "-c", args[1]] + args[2:], "python -c", entry)
        elif args[0].startswith("-"):
            err(entry, f"python: opsi tidak diizinkan: {args[0]}")
        else:
            script = (cwd / args[0]).resolve()
            if not inside_sandbox(script) or not script.is_file():
                err(entry, f"python: tidak bisa membuka '{args[0]}' (harus file di dalam sandbox)")
            else:
                start_process([sys.executable, "-u", str(script)] + args[1:], f"python {args[0]}", entry)

    # ---- pip ----
    elif cmd == "pip":
        pip = [sys.executable, "-m", "pip", "--disable-pip-version-check"]
        if args in (["list"], ["freeze"], ["--version"]):
            run_short(pip + args, entry)
        elif len(args) == 2 and args[0] == "show" and PKG_RE.match(args[1]):
            run_short(pip + args, entry)
        else:
            err(entry, "pip: hanya list | freeze | --version | show <paket> yang diizinkan")

    # ---- perintah dengan path ----
    elif cmd in PATH_COMMANDS:
        problem = validate_path_args(args)
        if problem:
            err(entry, f"{cmd}: {problem}")
        else:
            run_short([cmd] + args, entry)
    elif cmd in PLAIN_COMMANDS:
        run_short([cmd] + args, entry)
    else:
        err(entry, f"{cmd}: perintah tidak ditemukan atau tidak diizinkan (ketik 'help')")
    return True


# ---------------------------------------------------------------------------
# Riwayat (session_state + file)
# ---------------------------------------------------------------------------
def load_history() -> list:
    if PERSIST_HISTORY and HISTORY_FILE.exists():
        try:
            data = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
            clean = []
            for h in data[-MAX_HISTORY:]:
                segs = h.get("segs")
                if segs is None:  # kompatibel dengan versi lama
                    segs = [["out", nl(h.get("out", ""))]] if h.get("out") else []
                clean.append({"cwd": h.get("cwd", "~"), "cmd": h.get("cmd", ""), "segs": segs,
                              "size": sum(len(s[1]) for s in segs)})
            return clean
        except Exception:  # noqa: BLE001
            pass
    return []


def save_history() -> None:
    if not PERSIST_HISTORY:
        return
    try:
        HISTORY_FILE.write_text(
            json.dumps(st.session_state.history[-MAX_HISTORY:], ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception:  # noqa: BLE001
        pass


defaults = {
    "history": None,
    "cwd": ".",
    "prev_cwd": ".",
    "proc": None,
    "authed": False,
    "editing": None,
    "edit_initial": "",
    "edit_nonce": 0,
    "up_nonce": 0,
    "flash": "",
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v
if st.session_state.history is None:
    st.session_state.history = load_history()


# ---------------------------------------------------------------------------
# Tampilan (CSS)
# ---------------------------------------------------------------------------
st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600&display=swap');
.stApp { background: #000; }
[data-testid="stHeader"] { background: transparent; }
h1, h2, h3, p, label, span, div { color: #d6ffd6; }
.block-container { max-width: 1100px; padding-top: 1.5rem; }
.term-box {
    background: #000; border: 1px solid #1f6f1f; border-radius: 8px;
    box-shadow: 0 0 16px #00ff0033; height: 62vh; overflow-y: auto;
    display: flex; flex-direction: column-reverse;  /* auto-scroll ke baris terbaru */
    padding: 12px;
}
.term-inner {
    font-family: "Fira Code", "Courier New", Consolas, monospace; font-size: 14px;
    line-height: 1.5; white-space: pre-wrap; word-break: break-word; color: #39ff14;
}
.term-inner .prompt { color: #7dffb0; font-weight: 600; }
.term-inner .cmd { color: #ffffff; }
.term-inner .out { color: #e8ffe8; }
.term-inner .err { color: #ff4d4d; }
.term-inner .stdin { color: #6ee7ff; }
.term-inner .muted { color: #5fae5f; }
.term-inner .cursor { color: #39ff14; animation: blink 1s steps(1) infinite; }
@keyframes blink { 50% { opacity: 0; } }
[data-testid="stTextInput"] input {
    background: #000 !important; color: #39ff14 !important;
    font-family: "Fira Code", "Courier New", Consolas, monospace !important;
    border: 1px solid #1f6f1f !important;
}
.stButton > button, [data-testid="stFormSubmitButton"] > button {
    background: #0b2a0b; color: #39ff14; border: 1px solid #1f6f1f;
    font-family: "Fira Code", "Courier New", monospace;
}
.stButton > button:hover, [data-testid="stFormSubmitButton"] > button:hover {
    background: #14501a; color: #fff; border-color: #39ff14;
}
textarea { font-family: "Fira Code", "Courier New", monospace !important;
    background: #050505 !important; color: #e8ffe8 !important; }
</style>
""",
    unsafe_allow_html=True,
)

st.markdown("### 💻 Web Terminal")

# ---------------------------------------------------------------------------
# Login & peringatan
# ---------------------------------------------------------------------------
if PASSWORD and not st.session_state.authed:
    with st.form("login"):
        pw = st.text_input("Password terminal", type="password")
        if st.form_submit_button("Masuk"):
            if hmac.compare_digest(pw.encode(), PASSWORD.encode()):
                st.session_state.authed = True
                st.rerun()
            else:
                st.error("Password salah.")
    st.stop()

if ALLOW_PYTHON and not PASSWORD:
    st.error(
        "Eksekusi Python AKTIF tanpa password. Siapa pun yang membuka aplikasi ini bisa "
        "menjalankan kode di server. Isi TERMINAL_PASSWORD atau matikan TERMINAL_ALLOW_PYTHON."
    )
elif not PASSWORD:
    st.warning("Mode tanpa password. Aman untuk lokal, jangan deploy publik tanpa TERMINAL_PASSWORD.")

if st.session_state.flash:
    st.toast(st.session_state.flash)
    st.session_state.flash = ""


# ---------------------------------------------------------------------------
# Layar terminal (fragment: auto-refresh saat proses berjalan)
# ---------------------------------------------------------------------------
CLS = {"out": "out", "err": "err", "in": "stdin"}


def terminal_html() -> str:
    proc = st.session_state.proc
    parts = [
        '<span class="muted">Web Terminal siap. Ketik <b>help</b> untuk daftar perintah. '
        "Sandbox: ./sandbox</span>\n"
    ]
    for h in st.session_state.history:
        parts.append(
            f'<span class="prompt">user@streamlit:{escape(h["cwd"])}$</span> '
            f'<span class="cmd">{escape(h["cmd"])}</span>\n'
        )
        for tag, text in h["segs"]:
            parts.append(f'<span class="{CLS.get(tag, "out")}">{escape(text)}</span>')
        if proc and proc.entry is h:
            parts.append('<span class="cursor">█</span>')
    return "".join(parts)


def terminal_view() -> None:
    if drain() == "done":
        st.rerun()  # rerun penuh: hentikan polling & tampilkan prompt normal
    st.markdown(
        f'<div class="term-box"><div class="term-inner">{terminal_html()}</div></div>',
        unsafe_allow_html=True,
    )


run_every = POLL_INTERVAL if st.session_state.proc else None
st.fragment(terminal_view, run_every=run_every)()

# ---------------------------------------------------------------------------
# Status proses + input
# ---------------------------------------------------------------------------
proc = st.session_state.proc
if proc:
    c1, c2 = st.columns([6, 1])
    c1.markdown(
        f"<span style='color:#ffd866'>● berjalan: {escape(proc.label)} "
        f"— ketikan di bawah dikirim sebagai input (stdin)</span>",
        unsafe_allow_html=True,
    )
    if c2.button("⛔ Stop", use_container_width=True):
        proc.kill("dihentikan pengguna (Ctrl+C)")
        st.rerun()

with st.form("cmd_form", clear_on_submit=True):
    c1, c2 = st.columns([8, 1])
    placeholder = "stdin › ketik input untuk program lalu Enter" if proc else f"user@streamlit:{rel_cwd()}$ ketik perintah lalu Enter"
    text = c1.text_input("cmd", label_visibility="collapsed", placeholder=placeholder)
    submitted = c2.form_submit_button("Send" if proc else "Run", use_container_width=True)

if submitted:
    if st.session_state.proc:
        send_line(text)  # baris kosong juga boleh (menutup blok di interpreter)
        st.rerun()
    elif text.strip():
        entry = {"cwd": rel_cwd(), "cmd": text.strip(), "segs": [], "size": 0}
        record = execute(text, entry)
        if record:
            st.session_state.history.append(entry)
            st.session_state.history = st.session_state.history[-MAX_HISTORY:]
        if not st.session_state.proc:
            save_history()
        st.rerun()

# ---------------------------------------------------------------------------
# Editor file
# ---------------------------------------------------------------------------
if st.session_state.editing:
    rel = st.session_state.editing
    with st.container(border=True):
        st.markdown(f"**✏️ Editor:** `{rel}`")
        content = st.text_area(
            "isi file",
            value=st.session_state.edit_initial,
            height=300,
            key=f"editor_{st.session_state.edit_nonce}",
            label_visibility="collapsed",
        )
        b1, b2, _ = st.columns([1, 1, 5])
        if b1.button("💾 Simpan"):
            target = SANDBOX / rel
            if inside_sandbox(target) and len(content.encode("utf-8")) <= MAX_EDIT_BYTES:
                target.write_text(content, encoding="utf-8")
                st.session_state.flash = f"{rel} tersimpan"
                st.rerun()
            else:
                st.error("Tidak bisa menyimpan (di luar sandbox atau terlalu besar).")
        if b2.button("✖ Tutup"):
            st.session_state.editing = None
            st.rerun()

# ---------------------------------------------------------------------------
# Upload & kontrol
# ---------------------------------------------------------------------------
with st.expander("📤 Upload file ke folder aktif"):
    ups = st.file_uploader(
        "Pilih file (maks 5 MB)",
        accept_multiple_files=True,
        key=f"uploader_{st.session_state.up_nonce}",
    )
    if ups:
        saved = []
        for f in ups:
            name = Path(f.name).name
            target = current_dir() / name
            if f.size > MAX_UPLOAD:
                st.error(f"{name}: lebih dari 5 MB")
            elif not name or not inside_sandbox(target):
                st.error(f"{name}: nama file tidak valid")
            else:
                target.write_bytes(f.getvalue())
                saved.append(name)
        if saved:
            st.session_state.flash = "Terupload: " + ", ".join(saved)
            st.session_state.up_nonce += 1
            st.rerun()

k1, k2 = st.columns([1, 6])
if k1.button("🧹 Bersihkan"):
    st.session_state.history = []
    save_history()
    st.rerun()
k2.caption(
    f"Folder aktif: {rel_cwd()} · perintah singkat timeout {TIMEOUT_SECONDS} dtk · "
    f"proses Python maks {MAX_RUNTIME} dtk · Python "
    f"{'AKTIF' if ALLOW_PYTHON else 'nonaktif'}"
)
