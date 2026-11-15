# 2FA Codes (a wedgie app)

A TOTP authenticator for your [wedgie](https://wedgie.dev): the same 6-digit codes
your phone's authenticator app shows, generated on the wedgie from the secret keys
you type in once.

**What it is:** RFC 6238 TOTP (SHA-1, 6 or 8 digits, 30 s or 60 s) over pure
MicroPython, with a pure-Python SHA-1 fallback if the firmware's `hashlib` doesn't
have one. MIT, like everything wedgie.

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
is needed to reveal a code: presses a computer sends over USB never count.

## The clock (read this)

The Pico has no clock and no battery. The app sets its clock once from
`www.cloudflare.com` over the wedgie's net, then coasts on the crystal (a few
seconds a day at most). To set or re-set it, the wedgie needs its internet: its
page on [wedgie.dev](https://wedgie.dev/connect) open in a tab, or
`python3 wedgie.py net` in a terminal. Without a clock set, no codes.

## Saves

Two saves: `accounts` (a list of `{name, secret, digits, period, algo}`) and
`clock`. You can add an account by typing on the wedgie, or by editing the
`accounts` save on the /code emulator.

**Honest security note:** any plugged-in computer can read the wedgie's saves
without asking, so your 2FA secrets are readable over USB. Treat it as a backup
device for codes, not a vault: a phone left unlocked is worse, a hardware key is
better. Revealing a code always needs your physical green press.

## Try it

- Emulator: [wedgie.dev/code](https://wedgie.dev/code), open this folder (or this repo).
- Virtual wedgie (real firmware, real RAM): [wedgie.dev/connect](https://wedgie.dev/connect),
  **Apps from a GitHub repo**, this repo.
- Real wedgie: `python3 wedgie.py install .` (green press on the wedgie).
