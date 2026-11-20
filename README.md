# 2FA Codes (a wedgie app)

A TOTP authenticator for your [wedgie](https://wedgie.dev): the same 6-digit codes
your phone's authenticator app shows, generated on the wedgie from the secret keys
you type in once. **v2: the keys live in the Trust M chip's storage, not in its
saves.** RFC 6238 TOTP (SHA-1, 6 or 8 digits, 30 s or 60 s) over pure MicroPython,
with a pure-Python SHA-1 fallback if the firmware's `hashlib` doesn't have one. MIT,
like everything wedgie.

## Controls

| Button | What it does |
|---|---|
| up / down | pick an account |
| A (green) | show the code · press again to hide |
| joystick press | the menu: add an account, set the clock, line up the clock, delete this one, about |
| Y (red) | back out of a screen |
| B (grey) | delete a letter while typing |

Adding an account: type a short name (optional), then the site's base32 secret key
(from its 2FA setup page, the letters and digits without the spaces). A green press
is needed to reveal a code: presses a computer sends over USB never count. The next
code is shown small under it, so you can keep typing when the window flips; both
hide again when the code expires.

The key is typed on a 6×6 grid of letters and digits. up/down/left/right move, and
**A (green) or pressing the stick in picks the highlighted letter**; the bottom-right
cell is "ok", which files the key. A green press before the 8th letter does not
silently do nothing: the count turns red and says how many letters are still needed.

## The easy way: scan the QR with your Mac, not type 32 letters

The wedgie has no camera, so your computer reads the QR and hands the key over USB.
`import.py` (in this repo; put `wedgie.py` beside it - `curl -O https://wedgie.dev/wedgie.py` - and `pip install pyserial`) takes the `otpauth://`
link the QR holds - scan the QR with your phone camera to get it, or paste the link
the setup page copies - and parks it where the wedgie finds it on its next start:

```
python3 import.py "otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
```

Then press the wedgie's green button once (the save write asks), replug or restart
the app, and it asks **"Import 1 key?"** - green files it straight into the chip.
A QR screenshot works too if `brew install zbar` is done: `python3 import.py qr.png`.
Sites that show only the key: `python3 import.py --secret JBSWY3DPEHPK3PXP --name GitHub`.
It refuses what the wedgie cannot do (SHA-256, HOTP, 7 digits) with a plain sentence.

## Where the keys live (the honest security model)

- **With a Trust M chip (real wedgies):** each key is one line in a chip data object
  (`DATA[0..10]`, 11 accounts at most). The wedgie's saves are readable by any
  plugged-in computer *with no press at all*; the chip's storage is not. Getting a
  key out takes FULL CONTROL (a red warning screen and your green press) and, on
  firmware 0.3.79+, the "use the secure chip?" question too. First run offers to
  move any v1 keys from saves into the chip. This app never touches `DATA[11]` or
  the key slots (Safe Signer's) and never calls `set_metadata` (it can lock the chip
  for good). Expect one "use the secure chip?" green press per start.
- **Without a chip (the /code emulator), or if you answer no:** it falls back to
  saves, exactly like v1, and says "keys in saves" on the menu. Chipless also means no
  TLS, so the clock has to be handed over from a computer (see above).
- **What this is not:** the HMAC itself still runs on the Pico (a V1 Trust M has no
  HMAC), so a key is in RAM while its code is drawn. On a V3 chip, in-chip HMAC (the
  key never leaves) is the upgrade path, unimplemented until one can be tested for
  real.

## The clock (read this)

The Pico has no clock, no battery and no radio. It runs only while plugged in, so every
power-up needs a fresh time, and it can only reach the network through the computer it is
plugged into. That makes this a desk authenticator, not a pocket one.

- **With a Trust M chip:** it can ask `www.cloudflare.com` for the time (a "Setting the
  clock" page for a second or two). But note the wedgie has no radio: its internet is the
  computer it is plugged into, so the fetch only works while the wedgie's page is open at
  [wedgie.dev/connect](https://wedgie.dev/connect) or `python3 wedgie.py net` is running in
  a terminal. With no tether there is no net, and the app says so instead of hanging. After
  the fetch it coasts on the crystal, which drifts a second or two a day.
- **Drifting, or the site and the wedgie disagree:** menu → **line up the clock**. The
  screen shows the wedgie's own countdown as a big number; compare it with the site's
  countdown and dial it with up/down (1 s) and left/right (5 s) until the two match, then
  green. This is exact, and it is the only fix you need if the codes ever stop matching.
- **Without a chip** there is no TLS stack, so it cannot ask the net. Hand it the time
  from your computer with `python3 import.py --clock` (green press on the wedgie, then
  press A), then line it up as above if it is a second or two off.

A clock stamped before a reboot is thrown away rather than trusted: the uptime counter
restarts at zero, so an old stamp would be hours off.

## Saves

One save: `clock`. Accounts live in the chip (see above), or in an `accounts` save
in fallback mode (a list of `{name, secret, digits, period, algo}`), editable on the
/code emulator.

## Try it

- Emulator: [wedgie.dev/code](https://wedgie.dev/code), open this folder or this repo (no chip there: save mode).
- Virtual wedgie (real firmware, real RAM, software Trust M): [wedgie.dev/connect](https://wedgie.dev/connect), **Apps from a GitHub repo**, this repo.
- Real wedgie: `python3 wedgie.py install .` (green press on the wedgie).
