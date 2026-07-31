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
flag_generators/       60 generators — run on an existing Docker node to produce artifacts
flag_node_generators/  87 generators — emit a per-node docker-compose.yml that creates a challenge node
_packs_state.json      pack enable/disable state at time of export
```

Each generator directory holds a `manifest.yaml`, a `generator.py`, and for node
generators a `docker-compose.yml` (plus a `Dockerfile` where the image is built
locally). This matches the Generator Pack workspace layout, so a subtree here can
be zipped and imported through the Flag Catalog page.

## These are *installed* copies, not source packs

Directory names (`p_<pack-id>__<n>`) and manifest `id` values were rewritten at
install time — ScenarioForge assigns a new numeric id to every generator when a
pack is imported. The original identifier is preserved alongside it:

```json
{
  "generator_id": "7",
  "source_generator_id": "ssh_password_finance_terminal",
  "pack_label": "SSH",
  "origin": "flag_node_generators/ssh"
}
```

So `.coretg_pack.json` is the map back to the authoring pack. If you want to
restore clean source packs, group by `pack_id` and rename each directory and
manifest `id` to its `source_generator_id`.

## Why this repo exists

These live in `outputs/installed_generators/` in the ScenarioForge checkout,
which is gitignored. Manifest edits made there — notably the `hint_levels.high`
rewrites that replaced hints pointing at READMEs and generator manifests — were
one reinstall away from being lost.

## Authoring rules worth remembering

Participants only ever have the deployed scenario, so a hint must not reference a
README, the generator manifest, or `docker-compose.yml`; ScenarioForge filters
those lines out of node cards and both guides, which leaves the level empty. On a
flag-node-generator, `File(path)` is reserved for the compose file, so write
artifact hints against `FlagFile(path)`.

Full guidance: `docs/GENERATOR_AUTHORING.md` in the ScenarioForge repo.
