# 2FA Codes: a TOTP authenticator for your wedgie.
#   up/down  pick an account        A (green)  show / hide its code
#   press    the menu (add, clock, delete, about)      Y (red)  back
# The wedgie has no clock of its own, so "set the clock" asks cloudflare.com over its
# net (its page on wedgie.dev open in a tab, or `wedgie.py net`): after one set the
# codes coast on the Pico's crystal (seconds a day, at most).
# Your secrets live in a plain save: any plugged-in computer can read them without
# asking (code.md: never keep a secret in a save). Keep it as a backup device, not
# your only one. Showing a code needs a real press of the green button, never USB.
import time
import struct
import hashlib
from lcd import LCD, Keys
import save
import ui

lcd = LCD()
keys = Keys()                  # navigation: presses a computer sends are fine
real = Keys(physical=True)     # showing a code is a person's press, never USB's

TIME_URL = "https://www.cloudflare.com/cdn-cgi/trace"

# ---------------------------------------------------------------- sha-1 and hmac

# MicroPython builds differ: hashlib.sha256 is always there, sha1 sometimes not
# (the wedgie docs promise hashlib, not which parts). A pure-Python sha-1 costs a
# few ms per code (two 64-byte blocks, four in the hmac): fine once every 30 s.
class _SHA1:
    def __init__(self, data=b""):
        self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
        self.buf = b""
        self.n = 0
        if data:
            self.update(data)

    def update(self, data):
        self.n += len(data)
        b = self.buf + data
        while len(b) >= 64:
            self._block(b[:64])
            b = b[64:]
        self.buf = b

    def _block(self, b):
        w = list(struct.unpack(">16I", b))
        for i in range(16, 80):
            t = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
            w.append(((t << 1) | (t >> 31)) & 0xFFFFFFFF)
        h = self.h
        a, bb, c, d, e = h
        for i in range(80):
            if i < 20:
                f = (bb & c) | ((~bb & 0xFFFFFFFF) & d)
                k = 0x5A827999
            elif i < 40:
                f = bb ^ c ^ d
                k = 0x6ED9EBA1
            elif i < 60:
                f = (bb & c) | (bb & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = bb ^ c ^ d
                k = 0xCA62C1D6
            t = (((a << 5) | (a >> 27)) & 0xFFFFFFFF) + f + e + k + w[i]
            e = d
            d = c
            c = (bb << 30 | bb >> 2) & 0xFFFFFFFF
            bb = a
            a = t & 0xFFFFFFFF
        h[0] = (h[0] + a) & 0xFFFFFFFF
        h[1] = (h[1] + bb) & 0xFFFFFFFF
        h[2] = (h[2] + c) & 0xFFFFFFFF
        h[3] = (h[3] + d) & 0xFFFFFFFF
        h[4] = (h[4] + e) & 0xFFFFFFFF

    def digest(self):
        n = self.n
        b = self.buf + b"\x80" + b"\x00" * ((55 - n) % 64) + struct.pack(">Q", n * 8)
        for i in range(0, len(b), 64):
            self._block(b[i:i + 64])
        return struct.pack(">5I", *self.h)


_sha1 = hashlib.sha1 if hasattr(hashlib, "sha1") else _SHA1
SHAS = {"SHA1": _sha1, "SHA256": hashlib.sha256}


def hmac_sha(key, msg, sha):
    """RFC 2104, 64-byte block, any of SHAS as the hash."""
    if len(key) > 64:
        key = sha(key).digest()
    ipad = bytearray(64)
    opad = bytearray(64)
    for i in range(64):
        k = key[i] if i < len(key) else 0
        ipad[i] = k ^ 0x36
        opad[i] = k ^ 0x5C
    return sha(bytes(opad) + sha(bytes(ipad) + msg).digest()).digest()


# ---------------------------------------------------------------- base32, totp

B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def b32(s):
    """A base32 string (spaces, dashes and = ignored) to bytes."""
    bits = 0
    n = 0
    out = bytearray()
    for ch in s:
        if ch in " -=":
            continue
        v = B32.find(ch.upper())
        if v < 0:
            raise ValueError(ch)
        bits = (bits << 5) | v
        n += 5
        if n >= 8:
            n -= 8
            out.append((bits >> n) & 0xFF)
    return bytes(out)


def totp(ac, t):
    """RFC 6238/4226: the code for account ac at unix time t."""
    mac = hmac_sha(b32(ac["secret"]), struct.pack(">Q", t // ac["period"]), SHAS[ac.get("algo", "SHA1")])
    off = mac[-1] & 0x0F
    v = (((mac[off] & 0x7F) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3]) % (10 ** ac["digits"])
    s = str(v)
    return "0" * (ac["digits"] - len(s)) + s


# ---------------------------------------------------------------- state

accounts = []
clock = None          # {"t": unix at sync, "ms": ticks at sync}, or None
pick = 0              # the account on screen
shown = False         # a revealed code stays up for 30 s, then hides itself


def load():
    global accounts, clock
    accounts = save.load("accounts", [])
    clock = save.load("clock", None)


def store_accounts():
    try:
        save.store("accounts", accounts)
    except OSError:
        ui.page(lcd, "Flash full", [("its saves ran out of room.", ui.RED), ("delete one, then add.", ui.MUTED)], "{g} ok")
    load()


def now():
    """Unix seconds, or None before the first clock set. ticks_diff wraps safely."""
    if not clock:
        return None
    return clock["t"] + time.ticks_diff(time.ticks_ms(), clock["ms"]) // 1000


def ago():
    a = time.ticks_diff(time.ticks_ms(), clock["ms"]) // 1000
    if a < 90:
        return str(a) + "s ago"
    if a < 5400:
        return str(a // 60) + "m ago"
    if a < 129600:
        return str(a // 3600) + "h ago"
    return str(a // 86400) + "d ago"


def sync():
    """The wedgie has no clock: ask cloudflare's trace page for the time."""
    ui.progress("Setting the clock", "cloudflare.com", bar=False)
    try:
        import net
        txt = net.get(TIME_URL)
        i = txt.find("ts=")
        t = int(txt[i + 3:txt.find("\n", i)].split(".")[0])
    except Exception as e:                      # net.Error and the rest
        ui.page(lcd, "No clock", [(str(e)[:26], ui.RED), ("keep its page open on", ui.MUTED), ("wedgie.dev, or wedgie.py net", ui.MUTED)], "{g} back")
        wait_a()
        return False
    global clock
    old = now()
    clock = {"t": t, "ms": time.ticks_ms()}
    save.store("clock", clock)
    if old is not None:
        d = t - old
        ui.page(lcd, "Clock set", [("was " + ("%+d" % d if abs(d) > 1 else "right") + "s off", ui.INK if abs(d) < 30 else ui.RED), (ago() + " it was set", ui.MUTED)], "{g} ok")
        wait_a()
    return True


def wait_a():
    while True:
        k = keys.pressed()
        if "A" in k or "Y" in k or "press" in k:
            return
        time.sleep_ms(30)


# ---------------------------------------------------------------- screens

def grouped(s, n=4):
    return " ".join(s[i:i + n] for i in range(0, len(s), n))


def draw_main():
    d = lcd
    d.fill(ui.WHITE)
    ui.band(d)
    if accounts:
        a = accounts[pick]
        nm = a["name"][:26]
        d.text(nm, 4, 10, ui.INK)
        ix = "%d/%d" % (pick + 1, len(accounts))
        d.text(ix, 236 - 8 * len(ix), 10, ui.MUTED)
        t = now()
        if t is None:
            ui.say(d, "no clock", 96, ui.RED, 2)
            ui.say(d, "codes need the right time", 130, ui.MUTED)
            ui.say(d, "{g} clock  ·  press menu", 228, ui.MUTED)
        else:
            if shown:
                c = totp(a, t)
                if a["digits"] == 8:
                    c = c[:4] + " " + c[4:]
                else:
                    c = c[:3] + " " + c[3:]
                d.big_text(c, (240 - 24 * len(c)) // 2, 92, ui.INK, 3)
            else:
                d.big_text("......", (240 - 24 * 6) // 2, 92, ui.MUTED, 3)
            left = a["period"] - t % a["period"]
            d.text("%ds" % left, 236 - 16, 168, ui.MUTED)
            w = 160 * left // a["period"]
            d.fill_rect(40, 182, 160, 8, ui.GREY)
            if left <= 5:
                d.fill_rect(40, 182, w, 8, ui.RED)
            else:
                d.fill_rect(40, 182, w, 8, ui.GREEN)
            ui.say(d, "{g} show  ·  press menu", 228, ui.MUTED)
    else:
        ui.say(d, "2FA Codes", 60, ui.INK, 2)
        ui.say(d, "add your first account:", 100, ui.MUTED)
        ui.say(d, "its key, from the site's", 118, ui.MUTED)
        ui.say(d, "2FA setup page", 136, ui.MUTED)
        ui.say(d, "{g} add  ·  press menu", 228, ui.MUTED)
    d.show()


MENU = ("add an account", "set the clock", "delete this one", "about")


def menu():
    global shown, pick
    c = 0
    draw = True
    while True:
        if draw:
            d = lcd
            d.fill(ui.WHITE)
            ui.band(d)
            t = now()
            if t is None:
                d.text("no clock yet", 4, 10, ui.RED)
            else:
                try:
                    lt = time.localtime(t)
                    d.text("%02d:%02d · set %s" % (lt[3], lt[4], ago()), 4, 10, ui.INK)
                except Exception:
                    d.text("set " + ago(), 4, 10, ui.INK)
            for i, m in enumerate(MENU):
                col = ui.INK if i == c else ui.MUTED
                x = 8 if i == c else 12
                if i == 2 and not accounts:
                    col = ui.GREY
                d.text(m, x, 52 + i * 24, col)
            ui.say(d, "{g} pick  ·  {r} back", 228, ui.MUTED)
            d.show()
            draw = False
        k = keys.pressed()
        if "up" in k or "down" in k:
            c = (c + (len(MENU) - 1 if "up" in k else 1)) % len(MENU)
            draw = True
        if "Y" in k:
            return
        if "A" in k or "press" in k:
            m = MENU[c]
            if m == "add an account":
                add()
                return
            if m == "set the clock":
                sync()
                return
            if m == "delete this one" and accounts:
                a = accounts[pick]
                if ui.ask(lcd, "Delete " + a["name"] + "?", ["the site keeps working.", "add it again with its key."]):
                    del accounts[pick]
                    pick = 0
                    store_accounts()
                return
            if m == "about":
                ui.page(lcd, "2FA Codes", [("a TOTP authenticator,", ui.INK), ("like your phone's.", ui.INK),
                                           ("secrets live in its save:", ui.MUTED), ("a plugged-in computer", ui.MUTED),
                                           ("can read them. a backup", ui.MUTED), ("device, not your only one.", ui.MUTED)], "{g} back")
                wait_a()
                return
        time.sleep_ms(40)


# ---------------------------------------------------------------- keyboard

KB = B32                     # 32 letters: 5 rows of 6, then 2 + del + ok
COLS, ROWS, CW, CH, KY = 6, 6, 40, 28, 48


def kb_cell(i):
    return i % COLS, i // COLS


def kb_draw(prompt, s, cx, cy):
    d = lcd
    d.fill(ui.WHITE)
    ui.band(d)
    d.text(prompt, 4, 10, ui.INK)
    tail = s[-16:]
    d.text(((".." + tail) if len(s) > 16 else tail) or "-", 4, 28, ui.MUTED)
    d.text(str(len(s)), 236 - 8 * (2 if len(s) > 9 else 1), 28, ui.MUTED)
    for i in range(32):
        x, y = kb_cell(i)
        d.text(B32[i], x * CW + 17, y * CH + KY + 8, ui.INK)
    for j, lab in ((32, "<"), (33, "ok")):
        x, y = kb_cell(j)
        if j == 33:
            d.text("ok", x * CW + 15, y * CH + KY + 8, ui.GREEN_D)
        else:
            d.text("<", x * CW + 17, y * CH + KY + 8, ui.RED)
    d.rect(cx * CW + 2, cy * CH + KY + 2, CW - 4, CH - 4, ui.GREEN)
    d.rect(cx * CW + 3, cy * CH + KY + 3, CW - 6, CH - 6, ui.GREEN)
    ui.say(d, "{g} pick · {k} del · press ok", 228, ui.MUTED)
    d.show()


def keyboard(prompt, minimum=0):
    """Type with the joystick: A picks, B deletes, press (or the ok cell) finishes,
    Y quits. An arrow held down repeats: slowly at first, then fast."""
    s = ""
    cx = cy = 0
    rep = 0                   # the last move's ticks (0: none)
    delay = 350
    DIRS = (("left", -1, 0), ("right", 1, 0), ("up", 0, -1), ("down", 0, 1))
    kb_draw(prompt, s, cx, cy)
    while True:
        k = keys.pressed()
        if "A" in k:
            i = cy * COLS + cx
            if i == 32:
                s = s[:-1]
            elif i == 33:
                if len(s) >= minimum:
                    return s
            else:
                s += B32[i]
        if "B" in k:
            s = s[:-1]
        if "press" in k and len(s) >= minimum:
            return s
        if "Y" in k:
            if not s or ui.ask(lcd, "Throw it away?", ["what you typed is lost."]):
                return None
        moved = False
        for name, dx, dy in DIRS:
            if name in k:
                ncx, ncy = (cx + dx) % COLS, (cy + dy) % ROWS
                if ncy * COLS + ncx < 34:
                    cx, cy = ncx, ncy
                rep = time.ticks_ms()
                delay = 350
                moved = True
                break
            if keys.held(name):
                if rep and time.ticks_diff(time.ticks_ms(), rep) > delay:
                    ncx, ncy = (cx + dx) % COLS, (cy + dy) % ROWS
                    if ncy * COLS + ncx < 34:
                        cx, cy = ncx, ncy
                    rep = time.ticks_ms()
                    delay = 130
                    moved = True
                break
        if moved or k:
            kb_draw(prompt, s, cx, cy)
        time.sleep_ms(40)


def add():
    global shown, pick
    name = keyboard("name (or ok to skip)")
    if name is None:
        return
    secret = keyboard("the site's key", minimum=8)
    if secret is None:
        return
    digits = 8 if not ui.ask(lcd, "6 digits?", ["most sites use six."], yes="6", no="8") else 6
    period = 60 if not ui.ask(lcd, "30 seconds?", ["how long a code lives."], yes="30", no="60") else 30
    try:
        b32(secret)
    except ValueError:
        ui.page(lcd, "Bad key", ["that can't be a key.", "type it again."], "{g} back")
        wait_a()
        return
    if now() is None:
        sync()
    ac = {"name": (name or "ACCT %d" % (len(accounts) + 1)).upper()[:12], "secret": secret,
          "digits": digits, "period": period, "algo": "SHA1"}
    accounts.append(ac)
    pick = len(accounts) - 1
    store_accounts()
    shown = True


# ---------------------------------------------------------------- main loop

def run():
    global pick, shown
    load()
    shown = False
    drew = None          # the (second, account, shown) on screen now
    draw_main()
    while True:
        t = now()
        if drew != (t, pick, shown):
            draw_main()
            drew = (t, pick, shown)
        k = keys.pressed()
        rk = real.pressed()
        if "up" in k and len(accounts) > 1:
            pick = (pick + len(accounts) - 1) % len(accounts)
            shown = False
        if "down" in k and len(accounts) > 1:
            pick = (pick + 1) % len(accounts)
            shown = False
        if "press" in k:
            menu()
            drew = None
        if "A" in rk:
            if not accounts:
                add()
                drew = None
            elif t is None:
                sync()
                drew = None
            else:
                shown = not shown
                drew = None
        time.sleep_ms(100)
