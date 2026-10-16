# Provenance

Where MugVPN's parts come from and who holds the rights to them: what its licenses rest on.

## MugVPN's own code

- Every commit in this repository is by one identity, `tanderbold`, the project's owner; there are no outside
  contributions so far. "The MugVPN authors" in LICENSE means the owner.
- The code, tests, documentation and translations were written in development sessions with an AI coding assistant
  (Anthropic's Claude Code), directed, reviewed and committed by the owner. No code was taken from other projects
  except where a file says so (below).
- `tools/patch-openvpn-privsep.py` holds parts of OpenVPN and the owner's changes to it: GPL-2.0-only, with OpenVPN's
  linking exceptions extended to the changes (`LICENSES/OpenVPN-exceptions.txt`); the openvpn files it changes say so,
  with the date.

## Artwork

- Menu bar icons: drawn by code, `tools/icon/draw-menubar.swift`.
- Social preview: drawn by code, `tools/icon/social-preview.swift`.
- App icon: made from one 1024-pixel image by `tools/icon/prepare-icon.swift` and `tools/icon/make-icns.sh`; the
  origin of that image and the rights to it are to be recorded here by the owner.
- Screenshots on the site: taken by the interface tests in a virtual machine, of the app itself with test profiles.

## Third-party components

Listed with their versions, sources and full license texts in `THIRD-PARTY-NOTICES.txt` (openvpn, OpenSSL, LZ4,
LZO); each release carries their complete corresponding source (`tools/make-source.sh`).

## Open items for the owner

- The app icon's source image (above).
- Any employer's or client's claim on work done for MugVPN (none known): to be confirmed in writing if there could be.
- Outside contributions, should there be any: a Developer Certificate of Origin sign-off (`git commit -s`) on each,
  stated in a CONTRIBUTING file before the first one is taken.
