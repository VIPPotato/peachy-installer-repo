# Peachy Installer catalogue

Catalogue metadata for Peachy Installer: mod descriptions, author credits and the information the client needs to present each mod's delivery route. This repository keeps metadata separate from the native application and mod payloads. Signed snapshots authenticate catalogue data; installation support requires separate client capabilities and package qualification.

Each mod has one author-edited record under `mods/`. The catalogue builder turns these records into the client snapshot, including derived links and hashes, so contributors do not have to maintain duplicate entries, recipes or release details.

For a Steam Workshop mod, authors supply the game and item identifiers. Archive records also use the publisher's checked release metadata. Recommendations are optional and do not declare dependencies.

See [Contributing](CONTRIBUTING.md) for authoring, [Publishing](PUBLISHING.md) for signed updates, [catalogue settings](catalogue.json) for snapshot details and [mod records](mods/) for source data.
