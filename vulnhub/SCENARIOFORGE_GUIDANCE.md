# ScenarioForge Vulhub Guidance Export

This file summarizes the optional ScenarioForge guidance data generated for the pinned Vulhub catalog.

The detailed machine-readable export is `vulnhub/scenarioforge_guidance_index.json`. Each recipe also has an adjacent `scenarioforge.vuln.yaml` file with low, medium, and high hints plus walkthrough steps.

## Source

- Public source: <https://github.com/vulhub/vulhub>
- Snapshot commit: `3af973a39bd0988f288a53fa9ea4b82372774e58`
- License: MIT; see vulnhub/content/LICENSE
- Method: Aggregated from per-recipe scenarioforge.vuln.yaml files generated from the pinned public Vulhub documentation.

## Coverage

- Recipes with guidance: 306
- Top-level content groups covered: 140
- Complete low/medium/high coverage: 306
- Recipes with walkthrough steps: 306
- Total walkthrough steps: 620
- Recipes with primary CVE IDs: 235
- Recipes with published network ports: 304
- Recipes without published network ports: 2

## Validation

These checks were run against this generated dataset and the sibling ScenarioForge worktree:

```bash
python3 scripts/generate_vulnhub_hints.py --check
python3 -m unittest tests/test_vulnhub_hints.py
python3 -m pytest tests/test_vuln_capability_metadata.py tests/test_vulnerability_guidance_js.py
```

The generated YAML is source-grounded in the pinned public Vulhub README and Compose files. The hints include port discovery at medium level and CVE/source/reproduction detail at high level when that information is present in the source material.
