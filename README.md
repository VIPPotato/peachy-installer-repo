# Peachy Installer catalogue

This repository contains catalogue metadata and installation recipe data for Peachy Installer. The native application source is maintained separately. Mod packages stay in their authors' published releases.

## Current status

The catalogue lists Melatonin Access, Cookie Clicker Access, Frozen Cookies and Grandpa's Greenhouse. It contains no demonstration entries or mod payloads.

Melatonin's published Windows v1.4 ZIP has been downloaded and checked against GitHub's size and SHA-256. Its `version.json` records the release, resolved tag commit, ZIP identity and all 25 file paths, sizes and member hashes. The recipe's required paths are present. This metadata covers the Windows ZIP only; it does not qualify the macOS archive, loader/runtime compatibility or installation safety.

The three Cookie Clicker entries use Steam Workshop. Cookie Clicker Access links Frozen Cookies and Grandpa's Greenhouse as optional recommendations, with separate author credits. Workshop payload versions remain unknown: GitHub v15.0 describes the accessibility mod's separate GitHub distribution, not an observed Workshop version. A Workshop link does not prove subscription, local installation or in-game activation, and gives Peachy no file ownership.

The existing Peachy executable does not yet consume this repository. Catalogue integration, signature verification and production installation transactions remain application work. Creating or validating these files does not enable installation, update, uninstall or adoption of an existing mod.

## Repository files

- `catalog.json`: revision, generation and expiry times, repository origin, trust state and entry references with SHA-256 hashes.
- `entries/`: product identity, credits, descriptions, upstream sources, eligibility and supported typed actions.
- `recipes/`: game discovery, installed-version probes, declared package paths, loader requirements and existing-file policies.
- `releases/`: checked copies of publisher `version.json` metadata, not ZIP payloads.
- `schemas/`: JSON Schema definitions for catalogue entries, archive/Workshop recipes and Windows release metadata.
- `tools/validate_catalog.py`: offline structural and reference validation.
- `tools/release_metadata.py`: metadata-only generation and validation from a pinned published ZIP.
- `tests/`: validation regressions using disposable metadata copies.

The schemas accept pending-verification or withdrawn entries for the Windows x86 archive route and typed Steam Workshop handoffs. Workshop recipes have no archive, loader or game-file probe and allow no Peachy-managed install, update, uninstall or adoption. Local Workshop observation and native action dispatch remain unimplemented. The release schema retains explicit unqualified loader/runtime requirements; passing it does not make an artifact installable.

## Validate a checkout

Use Python 3.11 or later with the development dependency in `requirements-dev.txt`. Install dependencies in a project-local virtual environment rather than a global Python installation.

From the repository root:

```text
python tools/validate_catalog.py
python -m unittest discover -s tests -v
python -m tools.release_metadata validate --manifest releases/melatonin-access/v1.4/version.json
```

The tests require `TMPDIR` or `RUNNER_TEMP` to name an existing disposable scratch directory. They create and remove metadata copies there. They do not read Steam libraries, access GitHub or run the installer.

The catalogue validator checks schemas, duplicate JSON keys and identities, bounded relative paths, referenced-file hashes, entry/recipe/release identities, exact release and Workshop URLs, optional recommendation targets, expiry and disabled mutation actions. It makes no network requests and reports signature and package-byte verification as false. A successful result establishes metadata consistency, not fresh package-byte checks, publisher authentication or game compatibility.

For a byte check, add `--archive` and the path to the matching ZIP to the release-metadata validation command. The checker compares the archive digest and every member path, size and hash. It refuses unsafe paths, links, case collisions, encrypted files and excessive decompression, without extracting or executing payloads.

## Trust and release records

The initial snapshot is unsigned. Entry and recipe hashes bind the referenced bytes within that snapshot, but they do not authenticate its publisher. A production client must verify an authenticated snapshot against its own trusted key before allowing installation. Private signing keys do not belong in this repository. Snapshot revision and expiry are metadata for that future policy; the local validator does not maintain a client's accepted-revision history.

The publisher contract uses a `version.json` release asset. The checked Melatonin metadata describes the unchanged published Windows v1.4 ZIP, not the newer internal build with the same nominal version. The entry binds the metadata's exact bytes and public asset URL. The `legacyRelease` locator is retained to identify the original ZIP; it must agree with the manifest. A ZIP digest must never be used as an installed DLL digest.

`python -m tools.release_metadata generate --help` describes metadata generation. It requires saved public release JSON, the resolved tag commit, the selected asset ID and the matching downloaded ZIP. It records every file, refuses an existing output and leaves loader/runtime qualification pending. It never builds, downloads, installs or publishes anything. Generate metadata from each release's own bytes rather than reusing a previous version's manifest.

Unresolved dependencies and file policies keep the route unavailable. Existing unmanaged mods must not acquire Peachy ownership merely because their identity or nominal version is recognised. Internal and published builds can share a version number.

## Maintaining entries

Keep catalogue entries and recipes declarative. Do not add executable hooks, arbitrary commands, game binaries, personal installation paths, credentials or copied mod payloads. Review upstream identity, credits, compatibility and redistribution terms before adding another project.

Changing recipe bytes requires updating the recipe hash in its entry. Changing entry bytes requires updating the corresponding hash in the catalogue. Increase the revision and set appropriate generation and expiry times when publishing a replacement snapshot. Never relabel unverified metadata as installation-qualified to make a validation check pass.

No licence has been selected for the original material in this repository. Upstream projects retain their own licences; a catalogue entry grants no redistribution permission for their packages.
