# Agent Instructions

This repository generates synthetic IEC 60870-5-104 scenarios for defensive IDS research and lab evaluation.

## Safety Rules

- Do not add live network connection features.
- Do not add `--target`, `--host`, `--ip`, `--connect`, or command-sending behavior.
- Keep generated addresses, station identifiers, IOAs, and events synthetic.
- Keep the documentation focused on defensive testing, reproducible demos, and research notes.

## Good Agent Tasks

- Add new synthetic scenario families with clear detection intent.
- Add deterministic tests for packet/feature generation.
- Add metadata fields for MITRE ATT&CK for ICS mapping.
- Add JSON/CSV summaries for generated scenario outputs.
- Cross-link scenarios to `Scada-Agent-SafetyBench` where useful.

## Verification

Use the script-level help and compile checks:

```bash
python -m compileall .
python simulate_8_stages.py --help
python generate_attack_pcaps.py --list
```
