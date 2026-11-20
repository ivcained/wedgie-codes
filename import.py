#!/usr/bin/env python3
"""Put a site's 2FA key on your wedgie without typing it with the joystick.

The wedgie has no camera: YOUR COMPUTER reads the QR (or you paste the link it holds),
and this script hands the key over USB. On the wedgie, 2FA Codes then asks
"Import 1 key from your computer?" - one green press files it into the chip.

    python3 import.py "otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
    python3 import.py qr.png                 # a screenshot of the QR (needs zbarimg)
    pbpaste | python3 import.py -            # whatever is on the clipboard

Where the link comes from: every 2FA setup page shows the QR; on a phone, the camera
shows the otpauth:// link under it, or use a QR reader app and copy it. Some sites show
"can't scan? show the key" - the key alone works too:

    python3 import.py --secret JBSWY3DPEHPK3PXP --name GitHub

It needs wedgie.py beside it (curl -O https://wedgie.dev/wedgie.py) and pyserial.
The only press is the wedgie's own green one, for the save that carries the key over.
"""
import argparse
import base64
import json
import os
import shutil
import re
import subprocess
import sys
import time
import tempfile
from urllib.parse import unquote, parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
WEDGIE = os.path.join(HERE, "wedgie.py")
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
    name = label
    if issuer and label.lower().startswith(issuer.lower() + ":"):
        name = label[len(issuer) + 1:]
    elif ":" in label:
        name = label.split(":", 1)[1]
    if not name:
        name = issuer or "account"
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


def wedgie_py(*args):
    if not os.path.exists(WEDGIE):
        raise SystemExit("wedgie.py isn't here. Get it:  curl -O https://wedgie.dev/wedgie.py")
    cmd = [sys.executable, WEDGIE] + list(args)
    print("$ " + " ".join(cmd[1:]), flush=True)
    for attempt in (1, 2, 3):
        out = subprocess.run(cmd, text=True)
        if out.returncode == 0:
            return
        if attempt < 3:
            # the wedgie re-enumerates on USB for a second or two after it restarts
            print("(the wedgie wasn't answering; waiting 4 s and trying again)", flush=True)
            time.sleep(4)
    raise SystemExit("wedgie.py %s failed (see above)" % args[0])


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
    a = ap.parse_args()

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

    # the save the app looks for on its next start, merged into whatever is already there
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
    print("\nhanding %d key%s to the wedgie: press its green button when it asks."
          % (len(lines), "" if len(lines) == 1 else "s"))
    wedgie_py("saves", "restore", back)
    print("\nthen start 2FA Codes (menu -> about -> restart, or replug): it asks "
          "\"import %d key%s from your computer?\" - green files %s into the chip."
          % (len(lines), "" if len(lines) == 1 else "s", "it" if len(lines) == 1 else "them"))


if __name__ == "__main__":
    main()
