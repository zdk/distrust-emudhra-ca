# distrust-emudhra-ca

Distrust eMudhra's certificate authority issued certificates from compromised
intermediates (details: https://emudhra.we-have-a-problem.com/).
Your computer may still trust them.
So, this script checks, and if needed, make OS to stop trusting the two root CAs behind them.

Needs: `curl`, internet access, and `sudo` for the fix.

## 1. Get the script

    curl -fsSLO https://raw.githubusercontent.com/zdk/distrust-emudhra-ca/main/distrust-emudhra-ca.sh

## 2. Check

    sh distrust-emudhra-ca.sh

    platform: macos
    STILL TRUSTED  dv-g3b-emudhra       <- bad, go to step 3
    blocked        dv-g3b-aaa-emudhra   <- good

If both lines say `blocked`, you are done.

## 3. Fix

    sudo sh distrust-emudhra-ca.sh apply

This edits the system trust store, then runs the check again.

## Notes

- Browsers: Firefox, and Chrome on Linux, use their own trust store.
  This script does not touch them. See the advisory for browser steps.
- NixOS: scripts cannot edit a NixOS system. The script prints one line
  for you to add to configuration.nix, then rebuild as usual.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | both test hosts rejected; you are safe |
| 1 | a test host is still trusted, or apply failed (see stderr) |
| 2 | could not verify: no curl, host unreachable, or bad usage |

Platforms: macOS, Debian/Ubuntu, Alpine, Wolfi, Fedora/RHEL family,
openSUSE, Arch, FreeBSD, NetBSD.
