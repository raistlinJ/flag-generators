# flag-generators

ScenarioForge challenge generators — the flag-generator and flag-node-generator
catalogs, kept under version control so edits survive a pack reinstall.

**This repository is private, and should stay private.** 24 of the
flag-node-generators embed a literal SSH private key (`PRIVATE_KEY = """-----BEGIN
OPENSSH PRIVATE KEY-----`). Those keys are the answer to their challenges, so
publishing this repo would solve them for everyone. Nothing here contains
personal credentials, and no flag values are hardcoded — flags derive from
`seed` + `secret` at runtime.

## Layout

```
flag_generators/<pack>/<generator-id>/       60 generators across 11 packs
flag_node_generators/<pack>/<generator-id>/  87 generators across 11 packs
PACKS.md                                     pack inventory and provenance
```

A flag-generator runs on an existing Docker node and produces artifacts. A
flag-node-generator emits a per-node `docker-compose.yml` that *creates* a
challenge node.

Each generator directory holds `manifest.yaml`, `generator.py`, and for node
generators a `docker-compose.yml` (plus a `Dockerfile` where the image is built
locally).

## Reimporting a pack

Zip a pack directory and import it from the Flag Catalog page. The importer
locates manifests recursively and files each generator by the `kind` declared in
its manifest, so the enclosing directory names are for humans — they do not
affect where a generator lands.

Expect the ids to change: ScenarioForge assigns a **new numeric `id`** to every
generator on import and renames its directory to `p_<pack-id>__<n>`. The
authoring id in this repo is the stable one; the installed id is not, which is
why `PACKS.md` records the mapping from the last import.

## How this tree was reconstructed

These generators were exported from `outputs/installed_generators/` in the
ScenarioForge checkout, which holds *installed* copies. Two things were undone to
get back to source form:

- the manifest `id`, restored from `.coretg_pack.json` → `source_generator_id`
- the directory name, regrouped under the pack's `origin` path

Everything else is byte-identical to the installed copy. Two things could not be
undone: the original per-generator directory name (only the pack root is
recorded) and any `source` / `source_path` manifest keys, which the installer
drops. Directories are therefore named by generator id, which is unique across
all 147.

`PACKS.md` also lists the 40 generators whose authoring id had already been
overwritten by an earlier install cycle and could not be recovered.

## Why this repo exists

These live in a gitignored directory in the ScenarioForge checkout, so manifest
edits made there — notably the `hint_levels.high` rewrites that replaced hints
pointing at READMEs and generator manifests — were one pack reinstall away from
being lost.

## Authoring rules worth remembering

Participants only ever have the deployed scenario, so a hint must not reference a
README, the generator manifest, or `docker-compose.yml`; ScenarioForge filters
those lines out of node cards and both guides, which leaves the level empty. On a
flag-node-generator, `File(path)` is reserved for the compose file, so write
artifact hints against `FlagFile(path)`.

Full guidance: `docs/GENERATOR_AUTHORING.md` in the ScenarioForge repo.
