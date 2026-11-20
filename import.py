#!/usr/bin/env python3
"""Put a site's 2FA key on your wedgie without typing it with the joystick.

The wedgie has no camera, so something else reads the QR and hands the key over USB.
Pick whichever is least effort for you:

    python3 import.py "otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
    python3 import.py qr.png                 # a screenshot of the QR (needs zbarimg)
    pbpaste | python3 import.py -            # whatever is on the clipboard
    python3 import.py --secret «redacted-secret» --name GitHub

    python3 import.py --serve                # a page: paste the link, or drop the QR
                                             # screenshot; add --lan to scan from your phone
    python3 import.py --watch                # copy an otpauth:// link anywhere on this
                                             # computer and it lands on the wedgie

On the wedgie, 2FA Codes then asks "Import 1 key from your computer?" - one green press
files it into the chip.

--serve opens http://127.0.0.1:8765 in your browser: paste the link the site shows under
its QR, or drag the QR screenshot onto the page (decoded in the page itself, no install).
With --lan it also prints a phone address; open that on your phone, tap the button, and
the phone's camera reads the QR and sends the key here - the phone is the camera, this
computer is the USB half.

It needs wedgie.py beside it (curl -O https://wedgie.dev/wedgie.py) and pyserial.
The only press is the wedgie's own green one, for the save that carries the key over.
"""
import argparse
import base64
import json
import os
import queue
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
WEDGIE = os.path.join(HERE, "wedgie.py")
JSQR = os.path.join(HERE, "jsqr.min.js")     # QR decoding in the page, vendored (MIT)
B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def clean_key(s):
    """A site's key to the bare base32 the wedgie reads (spaces, dashes, = gone)."""
    out = []
    for ch in s.strip():
        if ch in " -=":
            continue
        up = ch.upper()
        if up not in B32:
            raise SystemExit("that key has a character no 2FA key uses: %r" % ch)
        out.append(up)
    if len(out) < 8:
        raise SystemExit("that key is too short (%d letters, 8 at least)" % len(out))
    return "".join(out)


def parse_otpauth(uri):
    """otpauth://totp/Issuer:me?secret=..&digits=6&period=30&algorithm=SHA1 -> a dict."""
    u = urlparse(uri.strip())
    if u.scheme != "otpauth":
        raise SystemExit("not an otpauth:// link")
    if u.netloc.lower() != "totp":
        raise SystemExit("only time-based codes (totp); this is %r" % u.netloc)
    q = parse_qs(u.query)
    if "secret" not in q:
        raise SystemExit("the link has no secret= in it")
    label = unquote(u.path.lstrip("/"))
    issuer = (q.get("issuer") or [""])[0]
    svc = label
    if issuer and label.lower().startswith(issuer.lower() + ":"):
        svc = label[len(issuer) + 1:]
    elif ":" in label:
        svc = label.split(":", 1)[1]
    # the wedgie shows one account per row: the site's name reads better than an email
    name = issuer or svc or "account"
    digits = int((q.get("digits") or ["6"])[0])
    if digits not in (6, 8):
        raise SystemExit("this site wants %d digits; the wedgie does 6 or 8" % digits)
    period = int((q.get("period") or ["30"])[0])
    algo = ((q.get("algorithm") or ["SHA1"])[0] or "SHA1").upper()
    if algo != "SHA1":
        raise SystemExit("this site wants %s; the wedgie does SHA1 codes (what nearly every "
                         "site uses)" % algo)
    return {"name": name, "secret": clean_key((q.get("secret") or [""])[0]),
            "digits": digits, "period": period, "algo": "SHA1"}


def read_qr(path):
    """The text inside a QR image, if zbar or zxing is installed."""
    for tool in (["zbarimg", "-q", "--raw", path],
                 ["python3", "-m", "zxing", path]):
        if shutil.which(tool[0]) or tool[0] == "python3":
            try:
                out = subprocess.run(tool, capture_output=True, text=True, timeout=60)
                if out.returncode == 0 and out.stdout.strip():
                    for line in out.stdout.splitlines():
                        if line.strip().lower().startswith("otpauth:"):
                            return line.strip()
            except Exception:
                pass
    raise SystemExit(
        "couldn't read the QR here (no QR reader installed).\n"
        "Easiest: scan the QR with your phone camera - it shows the otpauth:// link -\n"
        "and paste it:  python3 import.py 'otpauth://totp/...'\n"
        "Or run the page (paste it, or drop the screenshot):  python3 import.py --serve\n"
        "Or install a reader:  brew install zbar")


def packed(ac):
    """One account as the wedgie's vault line: name|secret|digits|period|algo(1=SHA1)."""
    return "|".join((ac["name"][:12], ac["secret"], str(ac["digits"]), str(ac["period"]), "1"))


def find_saves(obj, depth=0):
    """wedgie.py's backup: {"wedgie-saves": 1, "files": {"/saves/codes/accounts.json": base64}}.
    Returns that files dict, or None."""
    if isinstance(obj, dict):
        f = obj.get("files")
        if isinstance(f, dict):
            return f
        for v in obj.values():
            got = find_saves(v, depth + 1)
            if got is not None:
                return got
    if isinstance(obj, list):
        for v in obj:
            got = find_saves(v, depth + 1)
            if got is not None:
                return got
    return None


def save_path(name, mod="codes"):
    return "/saves/%s/%s.json" % (mod, name)


def read_save(files, name):
    """A save's value as the app sees it (its file is base64 of JSON)."""
    v = files.get(save_path(name))
    if not v:
        return None
    try:
        return json.loads(base64.b64decode(v).decode())
    except Exception:
        return None


def write_save(files, name, value):
    files[save_path(name)] = base64.b64encode(json.dumps(value).encode()).decode()


def wedgie_py(*args, quiet=False):
    if not os.path.exists(WEDGIE):
        raise SystemExit("wedgie.py isn't here. Get it:  curl -O https://wedgie.dev/wedgie.py")
    cmd = [sys.executable, WEDGIE] + list(args)
    if not quiet:
        print("$ " + " ".join(cmd[1:]), flush=True)
    for attempt in (1, 2, 3):
        out = subprocess.run(cmd, text=True, capture_output=quiet)
        if out.returncode == 0:
            return out
        if attempt < 3:
            # the wedgie re-enumerates on USB for a second or two after it restarts
            print("(the wedgie wasn't answering; waiting 4 s and trying again)", flush=True)
            time.sleep(4)
    raise SystemExit("wedgie.py %s failed (see above)" % args[0])


def hand_accounts(acs):
    """Write the keys into the app's import save (one green press moves it over)."""
    lines = [packed(ac) for ac in acs]
    tmp = tempfile.mkdtemp(prefix="wedgie-import-")
    back = os.path.join(tmp, "saves.json")
    wedgie_py("saves", "backup", back)
    with open(back) as f:
        doc = json.load(f)
    saves = find_saves(doc)
    if saves is None:
        raise SystemExit("wedgie.py's backup didn't look like saves; nothing was written")
    old = read_save(saves, "import")
    write_save(saves, "import", "\n".join([x for x in ([old] if isinstance(old, str) else []) + lines if x]))
    with open(back, "w") as f:
        json.dump(doc, f)
    wedgie_py("saves", "restore", back)
    return len(lines)


# ---------------------------------------------------------------- a queue, so only one
# thing talks to the wedgie at a time and the browser never waits on a green press
class Handover:
    def __init__(self, dry_run=False):
        self.q = queue.Queue()
        self.log = []
        self.busy = False
        self.dry_run = dry_run
        self.lock = threading.Lock()
        threading.Thread(target=self._work, daemon=True).start()

    def add(self, uri):
        """Queue an otpauth:// link (or an account dict). Returns (ok, message)."""
        try:
            ac = uri if isinstance(uri, dict) else parse_otpauth(uri)
        except SystemExit as e:
            return False, str(e)
        self.q.put(ac)
        self.note("queued %s (%d digits, %ds)" % (ac["name"], ac["digits"], ac["period"]))
        return True, "queued for %s" % ac["name"]

    def note(self, s):
        with self.lock:
            self.log.append("%s  %s" % (time.strftime("%H:%M:%S"), s))
            del self.log[:-40]

    def state(self):
        with self.lock:
            return {"busy": self.busy, "waiting": self.q.qsize(),
                    "dry_run": self.dry_run, "log": list(self.log)}

    def _work(self):
        while True:
            ac = self.q.get()
            with self.lock:
                self.busy = True
            try:
                if self.dry_run:
                    self.note("DRY RUN: would hand over %s" % packed(ac))
                else:
                    self.note("press green on the wedgie to let this key in...")
                    n = hand_accounts([ac])
                    self.note("handed %d key over; start 2FA Codes to file it in" % n)
            except BaseException as e:
                self.note("FAILED: %s" % (str(e)[:200] or type(e).__name__))
            finally:
                with self.lock:
                    self.busy = False
                self.q.task_done()


# ---------------------------------------------------------------- the pages
PAGE = """<!doctype html><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>2FA Codes - add a key</title>
<style>
 :root{color-scheme:light dark}
 body{font:16px/1.5 -apple-system,system-ui,sans-serif;max-width:640px;margin:0 auto;padding:24px}
 h1{font-size:20px;margin:0 0 4px} .sub{color:#777;margin:0 0 20px}
 label{display:block;font-weight:600;margin:20px 0 6px}
 input,textarea,button{font:inherit;width:100%;box-sizing:border-box}
 input,textarea{padding:10px;border:1px solid #bbb;border-radius:8px}
 button{padding:12px;border:0;border-radius:8px;background:#111;color:#fff;font-weight:600;margin-top:10px;cursor:pointer}
 #drop{border:2px dashed #bbb;border-radius:10px;padding:28px;text-align:center;color:#777;cursor:pointer}
 #drop.on{border-color:#111;color:#111}
 #log{font:13px/1.6 ui-monospace,monospace;white-space:pre-wrap;background:#f4f4f4;border-radius:8px;padding:12px;margin-top:18px;min-height:72px}
 #phone{display:none;margin-top:20px;padding:12px;border:1px solid #ddd;border-radius:8px;font-size:14px;color:#555}
 #phone a{color:inherit}
 @media (prefers-color-scheme:dark){input,textarea{background:#1b1b1b;color:#eee;border-color:#444}
  #log{background:#171717;color:#ddd} button{background:#eee;color:#111} #drop{border-color:#555;color:#999}
  #phone{border-color:#333;color:#aaa}}
</style>
<h1>Add a key to your wedgie</h1>
<p class=sub>Paste the link, or drop the QR screenshot. One green press on the wedgie files it in.</p>

<label for=u>1 &middot; Paste the otpauth:// link (sites show it under the QR)</label>
<input id=u placeholder="otpauth://totp/..." autocomplete=off spellcheck=false>
<button onclick=send()>Send it to the wedgie</button>

<label>2 &middot; Or drop a screenshot of the QR</label>
<div id=drop>drop the QR screenshot here, or click to pick a file</div>
<input id=f type=file accept="image/*" hidden>

<div id=phone></div>
<div id=log>ready.</div>

<script src="jsqr.js"></script>
<script>
function log(s){ const e = document.getElementById('log'); e.textContent = s + '\\n' + e.textContent; }
async function post(uri){
  const r = await fetch('add', {method:'POST', headers:{'content-type':'application/json'},
                                body: JSON.stringify({uri})});
  const j = await r.json();
  log((j.ok ? 'queued: ' : 'no: ') + j.msg);
}
function send(){ const v = document.getElementById('u').value.trim(); if(v) post(v); }
async function poll(){
  try{
    const j = await (await fetch('state')).json();
    const tail = (j.log || []).slice(-4).reverse();
    if(tail.length) document.getElementById('log').textContent = tail.join('\\n');
    const p = document.getElementById('phone');
    if(j.phone && !p.firstChild){
      const t = document.createElement('span');
      t.textContent = 'On your phone: open ';
      const a = document.createElement('b');
      a.textContent = j.phone;
      const rest = document.createElement('span');
      rest.textContent = ' and tap the button. The phone camera reads the QR and sends it here.';
      p.append(t, a, rest);
      p.style.display = 'block';
    }
  }catch(e){}
}
setInterval(poll, 1500); poll();

function decodeFile(file){
  if(!window.jsQR){ log('no QR decoder here (jsqr.min.js missing?) - paste the link instead'); return; }
  const img = new Image();
  img.onload = () => {
    const c = document.createElement('canvas');
    c.width = img.width; c.height = img.height;
    const x = c.getContext('2d'); x.drawImage(img, 0, 0);
    const d = window.jsQR(x.getImageData(0,0,c.width,c.height).data, c.width, c.height);
    if(d && d.data && d.data.toLowerCase().startsWith('otpauth:')) post(d.data);
    else log('no otpauth QR found in that image');
  };
  img.src = URL.createObjectURL(file);
}
const drop = document.getElementById('drop');
drop.onclick = () => document.getElementById('f').click();
document.getElementById('f').onchange = e => { if(e.target.files[0]) decodeFile(e.target.files[0]); };
drop.ondragover = e => { e.preventDefault(); drop.classList.add('on'); };
drop.ondragleave = () => drop.classList.remove('on');
drop.ondrop = e => { e.preventDefault(); drop.classList.remove('on');
  const f = e.dataTransfer.files[0]; if(f) decodeFile(f); };
document.getElementById('u').addEventListener('keydown', e => { if(e.key === 'Enter') send(); });
</script>
"""

PHONE = """<!doctype html><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Scan a 2FA QR</title>
<style>
 :root{color-scheme:dark} body{margin:0;background:#111;color:#eee;font:16px/1.5 -apple-system,system-ui,sans-serif}
 header{padding:16px} h1{font-size:18px;margin:0 0 4px} p{margin:0;color:#999;font-size:14px}
 video{width:100%;display:block;background:#000;max-height:70vh;object-fit:cover}
 button{width:calc(100% - 32px);margin:12px 16px;padding:14px;border:0;border-radius:10px;
        background:#3cd;color:#042;font:inherit;font-weight:700}
 #out{padding:0 16px 24px;font:13px/1.5 ui-monospace,monospace;color:#8d8}
</style>
<header><h1>Scan the site's 2FA QR</h1>
<p>The camera reads it here and hands the key to the wedgie on your computer.</p></header>
<video id=v playsinline muted></video>
<button id=b>Start the camera</button>
<div id=out>ready.</div>
<script src="jsqr.js"></script>
<script>
const out = s => document.getElementById('out').textContent = s;
async function start(){
  if(!window.jsQR){ out('no QR decoder loaded'); return; }
  try{
    const stream = await navigator.mediaDevices.getUserMedia({video:{facingMode:'environment'}});
    const v = document.getElementById('v'); v.srcObject = stream; await v.play();
    const c = document.createElement('canvas'), x = c.getContext('2d', {willReadFrequently:true});
    out('hold it over the QR...');
    (function tick(){
      if(v.readyState === v.HAVE_ENOUGH_DATA){
        c.width = v.videoWidth; c.height = v.videoHeight;
        x.drawImage(v, 0, 0, c.width, c.height);
        const d = window.jsQR(x.getImageData(0,0,c.width,c.height).data, c.width, c.height);
        if(d && d.data && d.data.toLowerCase().startsWith('otpauth:')){
          out('found it, sending...');
          fetch('add', {method:'POST', headers:{'content-type':'application/json'},
                        body: JSON.stringify({uri:d.data})})
            .then(r => r.json())
            .then(j => out(j.ok ? 'sent. press green on the wedgie.' : ('no: ' + j.msg)));
          return;
        }
      }
      requestAnimationFrame(tick);
    })();
  }catch(e){ out('the camera said no: ' + e.message); }
}
document.getElementById('b').onclick = start;
</script>
"""


def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def serve(args):
    box = Handover(dry_run=args.dry_run)
    token = secrets.token_urlsafe(6) if args.lan else ""
    host = "0.0.0.0" if args.lan else "127.0.0.1"
    base = "/t/%s/" % token if token else "/"
    phone_url = ("http://%s:%d%sphone" % (lan_ip(), args.port, base)) if token else None
    js = open(JSQR, "rb").read() if os.path.exists(JSQR) else b"window.jsQR=null;"

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="text/html; charset=utf-8"):
            b = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("content-type", ctype)
            self.send_header("content-length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def _path(self):
            p = self.path.split("?")[0]
            if token:
                if not p.startswith(base):
                    return None
                p = "/" + p[len(base):]
            return p

        def do_GET(self):
            p = self._path()
            if p is None:
                return self._send(404, "not here")
            if p in ("/", "/index.html"):
                return self._send(200, PAGE)
            if p == "/phone":
                return self._send(200, PHONE)
            if p == "/jsqr.js":
                return self._send(200, js, "application/javascript")
            if p == "/state":
                st = box.state()
                st["phone"] = phone_url if token else None
                return self._send(200, json.dumps(st), "application/json")
            return self._send(404, "not here")

        def do_POST(self):
            p = self._path()
            if p != "/add":
                return self._send(404, "not here")
            n = int(self.headers.get("content-length") or 0)
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
                uri = (body.get("uri") or "").strip()
            except Exception:
                return self._send(400, json.dumps({"ok": False, "msg": "bad JSON"}), "application/json")
            ok, msg = box.add(uri) if uri else (False, "empty")
            return self._send(200, json.dumps({"ok": ok, "msg": msg}), "application/json")

    srv = ThreadingHTTPServer((host, args.port), H)
    url = "http://127.0.0.1:%d%s" % (args.port, base)
    threading.Thread(target=srv.serve_forever, daemon=True).start()   # the page comes up now
    print("2FA Codes: open %s" % url)

    for i in range(24):
        print("\rwaiting for the wedgie" + "." * (i % 4) + "   ", end="", flush=True)
        try:
            out = wedgie_py("hello", quiet=True)
            if (out.stdout or "").strip().startswith("{"):
                print("\rthe wedgie is here.                          ")
                break
        except BaseException:
            pass
        time.sleep(1.5)
    else:
        print("\r(no wedgie answered on USB - plug it in and start this again)\n")

    if token:
        print("on your phone, open:  %s" % phone_url)
        print("(that address carries a one-off code: %s)" % token)
    print("paste the link, or drop the QR screenshot. Ctrl-C stops this.")
    if not args.no_open:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.shutdown()
        print("\nstopped.")


def watch(args):
    """Clipboard watcher: copy an otpauth:// link anywhere and it lands on the wedgie."""
    box = Handover(dry_run=args.dry_run)
    seen = ""
    print("watching the clipboard: copy an otpauth:// link, then press green on the wedgie.")
    if args.name:
        print("(a bare key on the clipboard is taken too, filed as %r)" % args.name)
    print("Ctrl-C stops this.")
    while True:
        try:
            txt = subprocess.run(["pbpaste"], capture_output=True, text=True, timeout=5).stdout
        except Exception:
            txt = ""
        txt = (txt or "").strip()
        if txt and txt != seen:
            seen = txt
            m = re.search(r"otpauth://\S+", txt)
            if m:
                ok, msg = box.add(m.group(0))
                print(("queued: " + msg) if ok else ("no: " + msg), flush=True)
            elif args.name and re.fullmatch(r"[A-Za-z2-7 =\-]{8,64}", txt):
                ok, msg = box.add({"name": args.name, "secret": clean_key(txt),
                                   "digits": args.digits or 6,
                                   "period": args.period or 30, "algo": "SHA1"})
                print(("queued: " + msg) if ok else ("no: " + msg), flush=True)
        time.sleep(0.8)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("where", nargs="?", help="an otpauth:// link, a QR image, or - for stdin")
    ap.add_argument("--secret", help="the setup key alone (when the site shows one)")
    ap.add_argument("--name", default="", help="the account's name on the wedgie")
    ap.add_argument("--digits", type=int, default=0)
    ap.add_argument("--period", type=int, default=0)
    ap.add_argument("--dry-run", action="store_true", help="print what would be imported")
    ap.add_argument("--clock", action="store_true",
                    help="hand your computer's time to the wedgie instead (no internet needed)")
    ap.add_argument("--serve", action="store_true", help="a page: paste the link or drop the QR")
    ap.add_argument("--watch", action="store_true", help="watch the clipboard for otpauth:// links")
    ap.add_argument("--lan", action="store_true", help="with --serve: also serve it to your phone")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-open", action="store_true", help="don't open a browser")
    a = ap.parse_args()

    if a.serve:
        return serve(a)
    if a.watch:
        return watch(a)

    acs = []
    if a.clock:
        tmp = tempfile.mkdtemp(prefix="wedgie-clock-")
        back = os.path.join(tmp, "saves.json")
        wedgie_py("saves", "backup", back)
        with open(back) as f:
            doc = json.load(f)
        saves = find_saves(doc)
        if saves is None:
            raise SystemExit("wedgie.py's backup didn't look like saves; nothing was written")
        write_save(saves, "clock_set", int(time.time()))
        with open(back, "w") as f:
            json.dump(doc, f)
        print("handing your computer's time to the wedgie: press its green button when it asks.")
        wedgie_py("saves", "restore", back)
        print("\nthen on the wedgie press green (or menu -> set the clock): it takes the time\n"
              "and the codes work without any internet.")
        return
    if a.secret:
        acs.append({"name": a.name or "account", "secret": clean_key(a.secret),
                    "digits": a.digits or 6, "period": a.period or 30, "algo": "SHA1"})
    elif a.where in (None, "-"):
        data = sys.stdin.read() if a.where == "-" else ""
        if not data.strip():
            ap.print_help()
            return
        for line in data.splitlines():
            if line.strip().lower().startswith("otpauth:"):
                acs.append(parse_otpauth(line))
    elif a.where.lower().startswith("otpauth:"):
        acs.append(parse_otpauth(a.where))
    elif a.where.lower().startswith(("http://", "https://")):
        raise SystemExit(
            "that's a web address, not the 2FA link.\n"
            "What the QR holds starts with otpauth:// - copy that link (or the setup key),\n"
            "or screenshot the QR and drop it on:  python3 import.py --serve")
    else:
        acs.append(parse_otpauth(read_qr(a.where)))

    if not acs:
        raise SystemExit("no otpauth:// link found")
    lines = [packed(ac) for ac in acs]
    for ac in acs:
        print("  %-12s %s digits, every %ds" % (ac["name"], ac["digits"], ac["period"]))
    if a.dry_run:
        print("\n".join(lines))
        return

    print("\nhanding %d key%s to the wedgie: press its green button when it asks."
          % (len(lines), "" if len(lines) == 1 else "s"))
    n = hand_accounts(acs)
    print("\nthen start 2FA Codes (menu -> about -> restart, or replug): it asks "
          "\"import %d key%s from your computer?\" - green files %s into the chip."
          % (n, "" if n == 1 else "s", "it" if n == 1 else "them"))


if __name__ == "__main__":
    main()
