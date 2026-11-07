# Contributing

Create or edit `mods/<slug>/mod.json`. The folder name is the entry ID. Use the game's slug and credit each contributor accurately. Keep snapshot revision and generation/expiry times in [`catalogue.json`](catalogue.json).

## Steam Workshop

Example only, shortened from [Frozen Cookies](mods/frozen-cookies/mod.json):

```json
{
  "name": "Frozen Cookies",
  "game": "cookie-clicker",
  "authors": [
    {"id": "erbkaiser", "name": "Erbkaiser", "role": "maintainer"}
  ],
  "description": "Automation and statistics for Cookie Clicker, maintained by Erbkaiser.",
  "repository": "erbkaiser/FrozenCookies",
  "workshop": {"appId": "1454400", "itemId": "2816199538"}
}
```

Required fields are `name`, `game`, `authors` and `description`. Each author needs `id` and `name`, with an optional `role`. Optional `repository` uses GitHub `owner/repo`; `category` defaults to `mods`. Supply exactly one `workshop` or `archive` route.

Keep each author's ID and display name consistent across records. Peachy derives its Author filter from these credits; there is no separate author list to edit. Adding a record using supported capabilities does not require a client rebuild.

Optional `recommendations` list an `entryId` and `reason` for each suggestion; they never declare dependencies. Set `withdrawn` to `true` to withdraw a record. An optional `blockers` list adds reasons it remains unavailable.

## Archives

Use [Melatonin Access](mods/melatonin-access/mod.json) for the `windows-x86-melonloader` profile and its game, probe, required-path, configuration and observation fields. Keep the checked publisher [`version.json`](mods/melatonin-access/version.json) beside `mod.json`, preserving its exact bytes. Release identifiers, asset details and hashes come from that file.

Set `verification` to `provider-metadata-only` or `archive-bytes-verified` only as supported by evidence. Checking archive bytes does not establish loader/runtime compatibility or enable installation. Other platforms, arbitrary commands and additional profiles are unsupported.

## Validate and build

Use Python 3.11 or later with `requirements-dev.txt` installed in a project-local virtual environment. From the repository root:

```text
python tools/validate_catalog.py
python tools/build_catalog.py --check
python tools/build_catalog.py
python tools/validate_catalog.py --root dist/catalogue
```

These commands are offline. The validator checks source records by default. Build `--check` validates without persistent output; a normal build generates the unsigned schema-1 client snapshot in `dist/catalogue`. Use `--output` to select another generated directory.

Do not edit generated output or maintain hashes, Workshop URLs, recipes or actions by hand. Rebuilding replaces only the builder's own unedited output and refuses unknown or changed files. Building does not download, install or publish.

Maintainers publish reviewed records through the [signed catalogue workflow](PUBLISHING.md). Contributors do not need a signing key or edits to a second entry list. Catalogue publication settings are maintained separately from individual mod records.
