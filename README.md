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
| joystick press | the menu: add, set the clock, delete, about |
| Y (red) | back out of a screen |
| B (grey) | delete a letter while typing |

Adding an account: type a short name (optional), then the site's base32 secret key
(from its 2FA setup page, the letters and digits without the spaces). A green press
is needed to reveal a code: presses a computer sends over USB never count. The next
code is shown small under it, so you can keep typing when the window flips; both
hide again when the code expires.

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
  saves, exactly like v1, and says "keys in saves" on the menu.
- **What this is not:** the HMAC itself still runs on the Pico (a V1 Trust M has no
  HMAC), so a key is in RAM while its code is drawn. On a V3 chip, in-chip HMAC (the
  key never leaves) is the upgrade path, unimplemented until one can be tested for
  real.

## The clock (read this)

The Pico has no clock and no battery. The app sets its clock once from
`www.cloudflare.com` over the wedgie's net, then coasts on the crystal (a few
seconds a day at most). To set or re-set it, the wedgie needs its internet: its
page on [wedgie.dev](https://wedgie.dev/connect) open in a tab, or
`python3 wedgie.py net` in a terminal. Without a clock set, no codes.

## Saves

One save: `clock`. Accounts live in the chip (see above), or in an `accounts` save
in fallback mode (a list of `{name, secret, digits, period, algo}`), editable on the
/code emulator.

## Try it

- Emulator: [wedgie.dev/code](https://wedgie.dev/code), open this folder or this repo (no chip there: save mode).
- Virtual wedgie (real firmware, real RAM, software Trust M): [wedgie.dev/connect](https://wedgie.dev/connect), **Apps from a GitHub repo**, this repo.
- Real wedgie: `python3 wedgie.py install .` (green press on the wedgie).
