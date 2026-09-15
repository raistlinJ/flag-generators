# ScenarioForge vulnerability catalog

Recipe READMEs are publicly available documentation.

## Import with notes and guidance

Select this entire `vulnhub` folder in the Vulnerability Catalog importer.
Include its hidden `.scenarioforge` folder. Selecting only `content` omits
catalog notes and validation state.

For a ZIP upload, run from the repository root:

```sh
python3 scripts/package_vulnhub_catalog.py ~/Downloads/scenarioforge-vulnhub-catalog.zip
```

The builder checks recipe coverage and ZIP integrity. The ZIP contains:

```text
.scenarioforge/catalog_notes.json       # Notes and their colors
.scenarioforge/catalog_items.json       # Validation and enable/disable state
content/<recipe>/docker-compose.yml
content/<recipe>/scenarioforge.vuln.yaml # Low/medium/high hints and steps
```

Notes and state identify recipes using paths such as
`content/airflow/CVE-2020-17526/docker-compose.yml`, relative to this folder.
Keep hints beside their corresponding compose file.

ScenarioForge's shared metadata discovery supports both this ZIP layout and
archives with a surrounding `vulnhub/` folder. Root metadata also supports older
importers that cannot find metadata beneath wrapper folders.

Choose **ZIP file**, import the generated archive, and **Set Active**. Existing
imports do not automatically acquire notes when the source repository changes.
