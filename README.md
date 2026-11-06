# Peachy Installer catalogue

This repository contains catalogue metadata and installation recipe data for Peachy Installer. The native application source is maintained separately. Mod packages stay in their authors' published releases.

## Current status

The initial catalogue lists Melatonin Access for Windows. It contains no demonstration entries.

Melatonin is pending verification. The Windows v1.4 release and asset identity were checked through GitHub metadata. The archive digest comes from GitHub; the package has not been downloaded or independently checked. The recipe's expected paths come from upstream packaging declarations. Loader and runtime compatibility remain unqualified.

The existing Peachy executable does not yet consume this repository. Catalogue integration, signature verification and production installation transactions remain application work. Creating or validating these files does not enable installation, update, uninstall or adoption of an existing mod.

## Repository files

- `catalog.json`: revision, generation and expiry times, repository origin, trust state and entry references with SHA-256 hashes.
- `entries/`: product identity, credits, descriptions, upstream sources, eligibility and supported typed actions.
- `recipes/`: game discovery, installed-version probes, declared package paths, loader requirements and existing-file policies.
- `schemas/`: JSON Schema definitions for the current catalogue, entry and recipe formats.
- `tools/validate_catalog.py`: offline structural and reference validation.
- `tests/`: validation regressions using disposable metadata copies.

The initial schema accepts pending-verification or withdrawn entries for the selected Windows x86 archive route. It does not represent an installation-qualified release. Broader delivery routes and enabled operations need reviewed schema and engine support.

## Validate a checkout

Use Python 3.11 or later with the development dependency in `requirements-dev.txt`. Install dependencies in a project-local virtual environment rather than a global Python installation.

From the repository root:

```text
python tools/validate_catalog.py
python -m unittest discover -s tests -v
```

The tests require `TMPDIR` or `RUNNER_TEMP` to name an existing disposable scratch directory. They create and remove metadata copies there. They do not read Steam libraries, access GitHub or run the installer.

The validator checks schemas, duplicate JSON keys and identities, bounded relative paths, referenced-file hashes, entry/recipe identities, release URL consistency, expiry and disabled mutation actions. It makes no network requests and reports signature and package-byte verification as false. A successful result establishes catalogue consistency, not publisher authentication or game compatibility.

## Trust and release records

The initial snapshot is unsigned. Entry and recipe hashes bind the referenced bytes within that snapshot, but they do not authenticate its publisher. A production client must verify an authenticated snapshot against its own trusted key before allowing installation. Private signing keys do not belong in this repository. Snapshot revision and expiry are metadata for that future policy; the local validator does not maintain a client's accepted-revision history.

The intended publisher contract uses a `version.json` asset beside each platform ZIP in its release. Melatonin's existing v1.4 release has no such asset, so its entry records an explicitly labelled legacy release identity. This record does not pretend to be a publisher manifest and does not change the upstream release. Its ZIP digest must never be used as the installed DLL digest.

Unresolved dependencies and file policies keep the route unavailable. Existing unmanaged mods must not acquire Peachy ownership merely because their identity or nominal version is recognised. Internal and published builds can share a version number.

## Maintaining entries

Keep catalogue entries and recipes declarative. Do not add executable hooks, arbitrary commands, game binaries, personal installation paths, credentials or copied mod payloads. Review upstream identity, credits, compatibility and redistribution terms before adding another project.

Changing recipe bytes requires updating the recipe hash in its entry. Changing entry bytes requires updating the corresponding hash in the catalogue. Increase the revision and set appropriate generation and expiry times when publishing a replacement snapshot. Never relabel unverified metadata as installation-qualified to make a validation check pass.

No licence has been selected for the original material in this repository. Upstream projects retain their own licences; a catalogue entry grants no redistribution permission for their packages.
