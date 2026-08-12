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
vulnhub/content/                              306 vulnerability recipes
vulnhub/vuln_list_w_url.csv                   vulnerability recipe index
PACKS.md                                     pack inventory and provenance
```

A flag-generator runs on an existing Docker node and produces artifacts. A
flag-node-generator emits a per-node `docker-compose.yml` that *creates* a
challenge node.

Each generator directory holds `manifest.yaml`, `generator.py`, and for node
generators a `docker-compose.yml` (plus a `Dockerfile` where the image is built
locally).

## Vulnerability catalog (`vulnhub/`)

**Snapshot taken 2026-05-27 at 14:40:12 local time.** This is the exact catalog
used by the 226-run batch archived in the sibling `scenarioforge-dataset`
repository. Its run metadata refers to catalog id
`05-27-26-14-40-12-f61521`.

Upstream provenance:

| | |
| --- | --- |
| Source | https://github.com/vulhub/vulhub |
| Commit | `3af973a39bd0988f288a53fa9ea4b82372774e58` |
| Commit date | 2026-01-13 |
| Installed as catalog | `05-27-26-14-40-12-f61521` on 2026-05-27 14:40:12 |
| Compose recipes | 306 across 148 applications |

The upstream content is from 2026-01-13 and was installed in the lab on
2026-05-27. Re-cloning Vulhub today would not reproduce the same catalog because
upstream has moved on, so this repository preserves the installed snapshot.

The installed catalog directory was 570 MB; this 104 MB copy omits the redundant
267 MB `catalog.zip`, 181 MB of nested Git history, and 17 MB of `__MACOSX/`
archive debris. Recipes live under `vulnhub/content/`, one directory per
application.

`vulnhub/vuln_list_w_url.csv` retains absolute paths from the machine that built
the catalog, so its `Path` column will not resolve in a fresh clone. Use the
portable `Name` column, which matches the `dir_rel` values in run metadata.

The file `vulnhub/content/git/CVE-2017-8386/id_rsa` is upstream Vulhub's
deliberately published fixture for that CVE, not a live credential, though
automated secret scanners will flag it. These applications are intentionally
vulnerable; do not run them on a network you care about.

## Reimporting a pack

Zip a pack directory, the repository root, or a downloaded repository ZIP and
import it from the Flag Catalog page. The importer locates manifests recursively,
files each generator by the `kind` declared in its manifest, and preserves the
category path between `flag_generators/` or `flag_node_generators/` and the
generator directory. For example, `flag_node_generators/http/example` remains in
the `http` category after import and export.

Expect the ids to change: ScenarioForge assigns a **new numeric `id`** to every
generator on import and renames only the final generator directory to
`p_<pack-id>__<n>` inside its original category. The authoring id in this repo is
the stable one; the installed id is not, which is why `PACKS.md` records the
mapping from the last import.

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
