# Prepared Citizen ATAK updates

Sanitized map definitions and verified phone-updater code for the S26/S24 profiles. This repository must not contain phone inventories, coordinates of private operations, server/channel settings, credentials, certificates, signing keys, chats, APKs or map-tile caches.

The maintained files are in `distribution/maps/` and `distribution/phone/`. A release contains a small archive for each phone, a manifest and detached signature, and a bootstrap. Imagery still comes directly from its providers. Live date selection remains automatic; installing code/configuration updates is deliberate, with backups and rollback.

Build a core candidate with Python 3.11 or later:

```sh
PYTHONPATH=src python scripts/build_wireless_release.py --output output/1.0.0 --version 1.0.0 --sequence 2026102201
```

On PowerShell set `$env:PYTHONPATH='src'` first. Increase the version and positive sequence for subsequent releases; use a new output directory. Unsigned candidates cannot be installed. A trusted publisher supplies an external RSA signing key using `--signing-key` and verifies the exact resulting assets before creating an immutable GitHub release. Production keys remain outside this repository. Desktop signing needs OpenSSL or an installed cryptography backend; the phone verifier requires OpenSSL.

`pc-atak-sources.zip` contains this rebuildable sanitized source tree. The large optional reference-data pack is separate; rebuilding it requires separately curated hash-bound data inputs in the author's private workspace and the `--references` switch. Do not commit those large files, terrain or private authoring evidence here. Static reference observations are dated data, not automatically current imagery.

Initial bootstrap must use a separately trusted file/hash and pinned public verification key. In Termux, the installed client supports:

```sh
python ~/.pc_atak_updates/pc_atak_update.py check
python ~/.pc_atak_updates/pc_atak_update.py apply --dry-run
python ~/.pc_atak_updates/pc_atak_update.py apply --yes
```

The daily job checks and stages new core versions; it never silently applies code, deletes caches or restarts ATAK. Reopen ATAK when ready to load changed definitions. Keep the prior working release and private recovery records. Offline Internet updates, reboot/Doze scheduling and field operation require their own validation.

NASA, USGS, Google, Bing and other map providers retain ownership and operation of their services. These source definitions are not offline tile copies or access credentials. Verify provider use terms and public data provenance before redistributing data packs.
