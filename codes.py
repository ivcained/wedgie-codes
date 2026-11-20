# 2FA Codes: a TOTP authenticator for your wedgie, v2 (the chip vault).
#   up/down  pick an account        A (green)  show / hide its code
#   press    the menu (add, clock, delete, about)      Y (red)  back
# The wedgie has no clock of its own, so "set the clock" asks cloudflare.com over its
# net (its page on wedgie.dev open in a tab, or `wedgie.py net`): after one set the
# codes coast on the Pico's crystal (seconds a day, at most).
# v2: account keys live in the Trust M chip's data objects (DATA[0..10]), not in its
# saves - saves are readable by any plugged-in computer with no press at all. Getting
# a key out now needs FULL CONTROL (a red screen and your green press) and, on 0.3.79+,
# the "use the secure chip?" question too. Never touched: DATA[11] and the key slots
# (Safe Signer's), and never set_metadata (it can lock the chip for good).
# With no chip (the /code emulator) or a "no" to the chip question it falls back to
# saves, exactly like v1 - and says so on the menu and the about page.
# Still true: the HMAC itself runs on the Pico (a V1 Trust M has no HMAC), so a key is
# in RAM while its code is drawn. Showing a code needs a real press of the green
# button, never USB's.
# Speed: the screen is pushed whole only when its content changes (an account switch,
# a reveal, a new code); every other second pushes only the countdown band
# (lcd.show(164, 196), ~3 ms instead of ~25), and the keyboard pushes only the cells
# that moved (show_rect, ~2 ms a key instead of ~32). A code is computed once per
# 30 s window, never per redraw, and a code that expired hides itself.
import time
import sys
import gc
import struct
import hashlib
from lcd import LCD, Keys
import save
import ui

lcd = LCD()
keys = Keys()                  # navigation: presses a computer sends are fine
real = Keys(physical=True)     # showing a code is a person's press, never USB's

TIME_URL = "https://www.cloudflare.com/cdn-cgi/trace"
VAULT_SLOTS = 11               # DATA[0..10]; DATA[11] is Safe Signer's

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


# ---------------------------------------------------------------- the chip vault

# One account per data object, as one line: name|secret|digits|period|algo
# (name 12, secret up to 64, params 1 each: 83 bytes at most, of 140).
ALGOS = {"SHA1": "1", "SHA256": "2"}
ALGOS_R = {"1": "SHA1", "2": "SHA256"}


def pack(ac):
    return "|".join((ac["name"], ac["secret"], str(ac["digits"]), str(ac["period"]),
                     ALGOS.get(ac.get("algo", "SHA1"), "1")))


def unpack(s):
    """An account from a vault line, or None if it isn't one of ours (another app's)."""
    p = s.split("|")
    if len(p) != 5:
        return None
    try:
        ac = {"name": p[0][:12], "secret": p[1], "digits": int(p[2]), "period": int(p[3]),
              "algo": ALGOS_R.get(p[4], "SHA1")}
    except ValueError:
        return None
    if not ac["name"] or not ac["secret"] or ac["digits"] not in (6, 8) or ac["period"] < 1:
        return None
    try:
        b32(ac["secret"])
    except ValueError:
        return None
    return ac


def vault_probe():
    """What's in the chip's data objects: (accounts, error). accounts is None on error
    (no chip, a refused chip question, an optiga error); [] means the chip works and
    holds nothing of ours. Unparseable non-empty objects are other apps': skipped,
    never reused."""
    try:
        import optiga
    except ImportError:
        return None, "no chip"
    try:
        c = optiga.Chip()
        out = []
        try:
            for i in range(VAULT_SLOTS):
                b = c.read(optiga.DATA[i])
                if b:
                    ac = unpack(b.decode())
                    if ac:
                        ac["_slot"] = i
                        out.append(ac)
        finally:
            c.close()
        return out, None
    except Exception as e:                     # optiga.Error, OSError, a refused chip
        return None, str(e)


def vault_write(i, ac):
    """One account into slot i. True: the chip read it back the same."""
    import optiga
    line = pack(ac).encode()
    c = optiga.Chip()
    try:
        c.write(optiga.DATA[i], line, erase=True)
        return c.read(optiga.DATA[i]) == line
    finally:
        c.close()


def vault_erase(i):
    import optiga
    c = optiga.Chip()
    try:
        c.write(optiga.DATA[i], b"", erase=True)
    finally:
        c.close()


def vault_free(used):
    for i in range(VAULT_SLOTS):
        if i not in used:
            return i
    return None


# ---------------------------------------------------------------- state

accounts = []         # in RAM while it runs (the hmac is computed on the Pico)
vault = False         # True: the chip holds the keys; False: saves do (v1 mode)
vault_err = None      # why the chip isn't in use, when it isn't
clock = None          # {"t": unix at sync, "ms": ticks at sync}, or None
pick = 0              # the account on screen
shown = False         # a revealed code hides itself when it expires


def has_trustm():
    """A Trust M this app could vault into? (wedgie.chip() says 'none' without one,
    and an ATECC608 can't: optiga is for the Trust M.)"""
    try:
        import wedgie
        return wedgie.chip() == "OPTIGA Trust M"
    except Exception:
        return False


def migrate(old):
    """v1 accounts (secrets in saves) move into the chip, all or nothing."""
    global accounts
    used = set(a["_slot"] for a in accounts)
    keep = []
    for a in old:
        i = vault_free(used)
        if i is None or not vault_write(i, a):
            ui.page(lcd, "Chip full or refused", [("your keys stay in its saves.", ui.INK),
                                                  ("nothing was moved.", ui.MUTED)], "{g} ok")
            wait_a()
            return False
        used.add(i)
        a["_slot"] = i
        keep.append(a)
    save.delete("accounts")
    accounts = keep
    return True


def load_accounts():
    """The accounts save as ONE string of packed lines (the browser-saves bridge of the
    /code emulator locks up on lists of dicts; a string saves everywhere)."""
    v = save.load("accounts", "")
    if isinstance(v, list):                    # a save an older build made
        return [a for a in v if a.get("secret")]
    out = []
    for line in (v or "").split("\n"):
        ac = unpack(line) if line else None
        if ac:
            out.append(ac)
    return out


def load():
    global accounts, vault, vault_err, clock
    vault = False
    vault_err = None
    clock = save.load("clock", None)
    accs, err = vault_probe()
    if accs is not None:
        old = load_accounts()
        if old and ui.ask(lcd, "Move your keys into the chip?",
                          ["they leave its saves, where", "a plugged-in computer", "reads them with no press."]):
            accounts = accs
            if migrate(old):
                vault = True
                return
        accounts = load_accounts()
        if not accounts:
            accounts = accs
            vault = True
            return
        vault_err = "keys are still in saves"
    else:
        vault_err = err or "chip off"
        accounts = load_accounts()
        sys.modules.pop("optiga", None)        # give its ~10 KB back


def store_accounts():
    """save mode only: the whole list back into the accounts save, one packed line each."""
    global accounts
    if vault:
        return
    try:
        save.store("accounts", "\n".join(pack(a) for a in accounts))
    except OSError:
        ui.page(lcd, "Flash full", [("its saves ran out of room.", ui.RED), ("delete one, then add.", ui.MUTED)], "{g} ok")
    accounts = load_accounts()


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
        gc.collect()                           # its ~30 KB back
        s = str(e)
        if "chip" in s or "Trust M" in s:
            # chipless (/code): TLS needs the chip, so there is no internet at all
            ui.page(lcd, "No clock", [("this emulator has no chip,", ui.RED),
                                      ("so no internet here.", ui.MUTED),
                                      ("a real wedgie sets its", ui.MUTED),
                                      ("clock in one press.", ui.MUTED)], "{g} back")
        elif "no internet" in s:
            ui.page(lcd, "No clock", [("its page is not open:", ui.RED),
                                      ("keep wedgie.dev/connect", ui.MUTED),
                                      ("open on this wedgie,", ui.MUTED),
                                      ("or run wedgie.py net", ui.MUTED)], "{g} back")
        else:
            ui.page(lcd, "No clock", [(s[:26], ui.RED), ("try again from the menu.", ui.MUTED)], "{g} back")
        wait_a()
        return False
    gc.collect()
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

_cached = (None, None, None, None)   # (the account, its code's window, the code, the next
                                     # one): both are computed once per window, never redrawn


def code_of(a, t):
    """(this window's code, the next window's) — the Ente-style peek under the big code."""
    global _cached
    w = t // a["period"]
    if _cached[0] is not a or _cached[1] != w:
        _cached = (a, w, totp(a, t), totp(a, t + a["period"]))
    return _cached[2], _cached[3]


def draw_main():
    """The main screen, into the framebuffer only: the caller pushes what changed."""
    print("DBG draw", len(accounts), shown)
    d = lcd
    d.fill(ui.WHITE)
    ui.band(d)
    if accounts:
        a = accounts[pick]
        nm = a["name"][:26]
        d.text(nm, 4, 10, ui.INK)
        ix = "%d/%d" % (pick + 1, len(accounts))
        d.text(ix, ui.right() - 8 * len(ix), 10, ui.MUTED)
        t = now()
        if t is None:
            ui.say(d, "no clock", 96, ui.RED, 2)
            ui.say(d, "codes need the right time", 130, ui.MUTED)
            ui.say(d, "{g} clock  ·  press menu", 228, ui.MUTED)
        else:
            if shown:
                c, nx = code_of(a, t)
                if a["digits"] == 8:
                    c = c[:4] + " " + c[4:]
                    nx = "next " + nx[:4] + " " + nx[4:]
                else:
                    c = c[:3] + " " + c[3:]
                    nx = "next " + nx[:3] + " " + nx[3:]
                d.big_text(c, (240 - 24 * len(c)) // 2, 84, ui.INK, 3)
                d.big_text(nx, (240 - 16 * len(nx)) // 2, 138, ui.MUTED, 2)
            else:
                d.big_text("......", (240 - 24 * 6) // 2, 92, ui.MUTED, 3)
            left = a["period"] - t % a["period"]
            d.text("%ds" % left, ui.right() - 16, 168, ui.MUTED)
            w = 160 * left // a["period"]
            d.fill_rect(40, 182, 160, 8, ui.GREY)
            if left <= 5:
                d.fill_rect(40, 182, w, 8, ui.RED)
            else:
                d.fill_rect(40, 182, w, 8, ui.GREEN)
            ui.say(d, "{g} show  ·  press menu", 228, ui.MUTED)
    else:
        ui.say(d, "2FA Codes", 46, ui.INK, 2)
        if not vault and has_trustm():
            ui.say(d, "its chip said no this start:", 76, ui.MUTED)
            ui.say(d, "answer its question, restart", 94, ui.MUTED)
            ui.say(d, "{g} try the chip  ·  press menu", 228, ui.MUTED)
        else:
            ui.say(d, "add your first account:", 92, ui.MUTED)
            ui.say(d, "its key, from the site's", 110, ui.MUTED)
            ui.say(d, "2FA setup page", 128, ui.MUTED)
            ui.say(d, "{g} add  ·  press menu", 228, ui.MUTED)


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
            d.text("keys in the chip" if vault else "keys in saves", ui.right() - 8 * 14, 10,
                   ui.GREEN_D if vault else ui.RED)
            for i, m in enumerate(MENU):
                col = ui.INK if i == c else ui.MUTED
                x = 8 if i == c else 12
                if i == 2 and not accounts:
                    col = ui.GREY
                d.text(m, x, 56 + i * 24, col)
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
                delete()
                return
            if m == "about":
                ui.page(lcd, "2FA Codes", [("a TOTP authenticator,", ui.INK), ("like your phone's.", ui.INK),
                                           ("keys in its Trust M:", ui.MUTED), ("reading them out of the", ui.MUTED),
                                           ("chip needs full control", ui.MUTED), ("and your green press.", ui.MUTED),
                                           ("(no chip: saves, like v1.)", ui.MUTED)], "{g} back")
                wait_a()
                return
        time.sleep_ms(40)


def delete():
    global pick, accounts
    a = accounts[pick]
    if not ui.ask(lcd, "Delete " + a["name"] + "?", ["the site keeps working.", "add it again with its key."]):
        return
    if vault:
        try:
            vault_erase(a["_slot"])
        except Exception as e:
            ui.page(lcd, "Chip error", [(str(e)[:26], ui.RED), ("the key may still be", ui.MUTED), ("in the chip.", ui.MUTED)], "{g} ok")
            wait_a()
            return
        accounts = [x for x in accounts if x is not a]
        pick = 0
    else:
        del accounts[pick]
        pick = 0
        store_accounts()


# ---------------------------------------------------------------- keyboard

KB = B32                     # 32 letters: 5 rows of 6, then 2 + del + ok
COLS, ROWS, CW, CH, KY = 6, 6, 40, 27, 52   # KY: the grid starts under the waistband


def kb_cell(i):
    return i % COLS, i // COLS


def kb_render(prompt, s, cx, cy, minimum=0, blocked=False):
    """The keyboard, into the framebuffer only. The caller pushes what changed: the
    typed line on a letter, the two cells on a cursor move, everything after an ask."""
    d = lcd
    d.fill(ui.WHITE)
    ui.band(d)                    # the waistband sits at y 10..33: nothing goes there
    d.text(prompt, 4, 10, ui.INK)
    if blocked and len(s) < minimum:
        ui.say(d, "need %d more" % (minimum - len(s)), 36, ui.RED)
    else:
        tail = s[-26:]
        d.text(((">>" + tail) if len(s) > 26 else tail) or "-", 4, 36, ui.MUTED)
    count = str(len(s))
    cc = ui.RED if len(s) < minimum else ui.MUTED
    d.text(count, ui.right() - 8 * len(count), 36, cc)
    for i in range(32):
        x, y = kb_cell(i)
        d.text(B32[i], x * CW + 17, y * CH + KY + 8, ui.INK)
    for j in (32, 33):
        x, y = kb_cell(j)
        if j == 33:
            d.text("ok", x * CW + 15, y * CH + KY + 8, ui.GREEN_D)
        else:
            d.text("<", x * CW + 17, y * CH + KY + 8, ui.RED)
    d.rect(cx * CW + 2, cy * CH + KY + 2, CW - 4, CH - 4, ui.GREEN)
    d.rect(cx * CW + 3, cy * CH + KY + 3, CW - 6, CH - 6, ui.GREEN)
    ui.say(d, "{g} pick · {k} del · press ok", 228, ui.MUTED)


def keyboard(prompt, minimum=0):
    """Type with the joystick: A (or X) picks, B deletes, press (or the ok cell)
    finishes, Y quits. An arrow held down repeats: slowly at first, then fast."""
    s = ""
    cx = cy = 0
    rep = 0                   # the last move's ticks (0: none)
    delay = 350
    blocked = False           # an ok came while still short of the minimum
    DIRS = (("left", -1, 0), ("right", 1, 0), ("up", 0, -1), ("down", 0, 1))
    kb_render(prompt, s, cx, cy, minimum)
    lcd.show()
    full = False              # an ask covered the screen: redraw it all
    while True:
        k = keys.pressed()
        was = (cx, cy, s, blocked)
        if "A" in k or "X" in k:
            i = cy * COLS + cx
            if i == 32:
                s = s[:-1]
            elif i == 33:
                blocked = len(s) < minimum
                if not blocked:
                    return s
            else:
                s += B32[i]
        if "B" in k:
            s = s[:-1]
        if "press" in k:
            blocked = len(s) < minimum
            if not blocked:
                return s
        if "Y" in k:
            if not s or ui.ask(lcd, "Throw it away?", ["what you typed is lost."]):
                return None
            full = True
        if k:
            if s != was[2]:
                blocked = False   # typed or deleted: back to the tail
            elif "Y" not in k and "press" not in k and "A" not in k and "X" not in k:
                blocked = False   # a plain move: the "need more" line goes away
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
        if (cx, cy, s, blocked) != was or full:
            kb_render(prompt, s, cx, cy, minimum, blocked)
            if full:
                lcd.show()
                full = False
            elif s != was[2] or blocked != was[3]:
                lcd.show_rect(0, 30, 240, 22)               # the typed line and count
            else:
                ox, oy = was[0], was[1]                     # only the cursor moved
                lcd.show_rect(ox * CW, oy * CH + KY, CW, CH)
                if (ox, oy) != (cx, cy):
                    lcd.show_rect(cx * CW, cy * CH + KY, CW, CH)
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
    if vault:
        used = set(a["_slot"] for a in accounts)
        i = vault_free(used)
        if i is None:
            ui.page(lcd, "Chip full", [("its 11 key slots are all", ui.INK), ("taken. delete one first.", ui.MUTED)], "{g} back")
            wait_a()
            return
        try:
            ok = vault_write(i, ac)
        except Exception as e:
            ui.page(lcd, "Chip error", [(str(e)[:26], ui.RED), ("the key isn't saved.", ui.MUTED)], "{g} back")
            wait_a()
            return
        if not ok:
            ui.page(lcd, "Chip mismatch", [("it read back different.", ui.RED), ("try again.", ui.MUTED)], "{g} back")
            wait_a()
            return
        ac["_slot"] = i
        accounts.append(ac)
    else:
        accounts.append(ac)
        store_accounts()
    gc.collect()
    pick = len(accounts) - 1
    shown = True


# ---------------------------------------------------------------- main loop

def run():
    global pick, shown
    load()
    gc.collect()             # the chip probe and the optiga import's leavings
    shown = False
    drew = None              # (account, shown, its code window) now on screen
    drew_t = None            # the second now on screen
    tick = None              # the window the shown code is from
    draw_main()
    lcd.show()
    while True:
        t = now()
        if accounts:
            w = t // accounts[pick]["period"] if t is not None else None
            if shown and tick is not None and w != tick:
                shown = False            # that code expired: hide it
            tick = w
        else:
            tick = None
        key = (pick, shown, tick if shown else None)
        if key != drew:
            print("DBG full show", key)
            draw_main()
            lcd.show()                   # the whole screen changed
            drew, drew_t = key, t
        elif t != drew_t:
            draw_main()
            lcd.show(164, 196)           # only the countdown moved (~3 ms)
            drew_t = t
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
            keys.pressed(); real.pressed()   # presses used up inside a long flow must not fire again
            drew = None
        if "A" in rk:
            if not accounts and not vault and has_trustm():
                load()                    # maybe its chip question gets a yes this time
                keys.pressed(); real.pressed()
                drew = None
            elif not accounts:
                add()
                keys.pressed(); real.pressed()
                drew = None
            elif t is None:
                sync()
                keys.pressed(); real.pressed()
                drew = None
            else:
                shown = not shown
                drew = None
        time.sleep_ms(100)
