# IEC 60870-5-104 Threat Scenario Generator

An 8-stage IEC-104 attack scenario simulator that generates realistic PCAP traffic and feature vectors for ICS/SCADA cybersecurity research. Each stage maps to a [MITRE ATT&CK for ICS](https://attack.mitre.org/techniques/ics/) technique, progressing from reconnaissance through impact.

Based on the methodology described in:

> **Threat Scenario Generation for IEC104 Cyber Defense**
> ResearchGate: [Publication 382158810](https://www.researchgate.net/publication/382158810_Threat_Scenario_Generation_for_IEC104_Cyber_Defense)

## Attack Stages

| Stage | Name | MITRE ICS | Tactic | Description |
|-------|------|-----------|--------|-------------|
| 1 | Discovery | [T0888](https://attack.mitre.org/techniques/T0888/) | Discovery | C_IC_NA_1 interrogation sweep across 20 station addresses |
| 2 | Monitor Process State | [T0801](https://attack.mitre.org/techniques/T0801/) | Collection | Frequent C_RD_NA_1 reads on 5 target IOAs every 2s |
| 3 | Automated Collection | [T0802](https://attack.mitre.org/techniques/T0802/) | Collection | Persistent polling loop: 50 IOAs every 3s for 60s |
| 4 | Command & Control | [T0869](https://attack.mitre.org/techniques/T0869/) | Command and Control | Secondary HMI session with STARTDT + TESTFR keepalives |
| 5 | Brute Force I/O | [T0806](https://attack.mitre.org/techniques/T0806/) | Impair Process Control | IOA sweep: C_SC_NA_1 on IOAs 100-2000 at 33 cmd/sec |
| 6 | Modify Parameter | [T0836](https://attack.mitre.org/techniques/T0836/) | Impair Process Control | C_SE_NA_1 setpoint changes on 5 safety-critical IOAs |
| 7 | Unauthorized Command | [T0855](https://attack.mitre.org/techniques/T0855/) | Impair Process Control | Command injection with invalid/missing COT sequences |
| 8 | Manipulation of Control | [T0831](https://attack.mitre.org/techniques/T0831/) | Impact | Rapid contradictory open/close on 3 breaker IOAs (20 cycles) |

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Generate all 8 stages (PCAPs + feature vectors)
python simulate_stages.py --output-dir output

# Generate a single stage
python simulate_stages.py --stage 5 --output-dir output

# Generate feature vectors only (no PCAPs)
python simulate_stages.py --features-only

# Generate + evaluate through protocol rules
python simulate_stages.py --evaluate-rules --output-dir output
```

## Output

Running the generator produces the following in the output directory:

```
output/
  stage_1_T0888.pcap          # Discovery sweep
  stage_2_T0801.pcap          # Monitor reads
  stage_3_T0802.pcap          # Automated polling
  stage_4_T0869.pcap          # C2 session
  stage_5_T0806.pcap          # Brute force IOA sweep
  stage_6_T0836.pcap          # Parameter modification
  stage_7_T0855.pcap          # Unauthorized commands
  stage_8_T0831.pcap          # Control manipulation
  all_stages_combined.pcap    # All stages merged, time-sorted
  stage_features.json         # Feature vectors for all 8 stages
```

PCAPs can be opened in [Wireshark](https://www.wireshark.org/) with the built-in IEC 60870-5-104 dissector.

## Protocol Rule Engine

The included rule engine provides signature-based detection for known IEC-104 attack patterns and protocol violations. Rules are defined in YAML and evaluated against extracted traffic features.

### 19 Detection Rules

**Attack pattern rules** (`protocol/rules/iec104_attack_patterns.yaml`):

| Rule | Pattern | Severity | MITRE |
|------|---------|----------|-------|
| IEC104-ATK-001 | Industroyer2-style command sequence | Critical | T0855 |
| IEC104-ATK-002 | Single IOA target concentration | High | T0836 |
| IEC104-ATK-003 | IOA sweep / enumeration | High | T0846 |
| IEC104-ATK-010 | Excessive general interrogation | High | T0814 |
| IEC104-ATK-011 | High event rate (>20/sec) | High | T0814 |
| IEC104-ATK-020 | Link restart without TESTFR | High | T0855 |
| IEC104-ATK-021 | Excessive STOPDT activity | High | T0814 |
| IEC104-ATK-022 | Failed keepalive pattern | Medium | T0814 |
| IEC104-ATK-030 | Sequence number discontinuity | Medium | T0820 |
| IEC104-ATK-031 | Sequence reset without link restart | Critical | T0855 |

**Protocol compliance rules** (`protocol/rules/iec104_protocol.yaml`):

| Rule | Violation | Severity | MITRE |
|------|-----------|----------|-------|
| IEC104-PROTO-001 | Invalid TypeID | High | T0855 |
| IEC104-PROTO-002 | Invalid/reserved COT | High | T0855 |
| IEC104-PROTO-003 | Invalid TypeID+COT combination | Critical | T0855 |
| IEC104-PROTO-004 | Error COT response | Medium | T0846 |
| IEC104-PROTO-010 | Command from unexpected direction | Critical | T0843 |
| IEC104-PROTO-020 | Excessive unique TypeIDs (fuzzing) | Medium | T0846 |
| IEC104-PROTO-021 | High command-to-monitor ratio | High | T0855 |
| IEC104-PROTO-022 | Rapid command rate (>1 cmd/sec) | Critical | T0855 |
| IEC104-PROTO-023 | Non-standard port usage | Medium | T0820 |

### Rule Evaluation Example

```python
from protocol.rule_engine import RuleEngine

engine = RuleEngine()

# Evaluate features from a traffic window
features = {
    "command_rate": 33.3,
    "unique_ioas": 1901,
    "dominant_type_ratio": 1.0,
    "orig_command_count": 1901,
    "is_missing_unique_ioas": 0,
    "events_per_second": 33.3,
}

matches = engine.evaluate_window(features)
for m in matches:
    print(f"[{m.severity}] {m.rule_name} ({m.mitre_ics.get('technique_id', '')})")
```

## IEC-104 Protocol Knowledge Base

`protocol/iec104_knowledge.py` encodes the IEC 60870-5-101/104 specification:

- **TypeID classification**: Monitor (1-44), Command (45-69), System (70-109), Parameter (110-119), File Transfer (120-127)
- **COT codes**: All 46 standard Cause of Transmission values
- **Valid TypeID x COT matrix**: Per IEC 60870-5-101 Table 14
- **Zeek string-to-numeric COT mapping**: For integration with Zeek IEC-104 analyzer
- **Industroyer2 indicators**: Known attack signatures from the 2022 Ukraine grid attack

## Project Structure

```
iec104-threat-scenarios/
  simulate_stages.py           # 8-stage overt attack scenario generator
  simulate_stealth_attacks.py  # 5-scenario stealth attack simulator
  requirements.txt             # Python dependencies (pyyaml only)
  protocol/
    __init__.py
    iec104_knowledge.py        # IEC-104 protocol specification
    rule_engine.py             # YAML-based detection rule engine
    rules/
      iec104_attack_patterns.yaml   # 10 attack pattern rules
      iec104_protocol.yaml          # 9 protocol compliance rules
  pcaps/                       # Pre-generated PCAP files
    stage_1_T0888.pcap
    ...
    all_stages_combined.pcap
    stage_features.json        # Feature vectors for all 8 stages
```

## Feature Vectors

Each stage produces a feature dictionary with IEC-104 traffic characteristics:

| Feature | Description | Unit |
|---------|-------------|------|
| `n_events` | Total IEC-104 events in window | count |
| `events_per_second` | Event rate | events/sec |
| `unique_typeIDs` | Distinct TypeID values | count |
| `unique_ioas` | Distinct IOA addresses | count |
| `unique_common_addresses` | Distinct station addresses | count |
| `command_rate` | Command events per second | cmds/sec |
| `command_vs_monitor_ratio` | Commands / monitor events | ratio |
| `orig_event_ratio` | Fraction of originator events | 0-1 |
| `dominant_type_ratio` | Most common TypeID / total | 0-1 |
| `dominant_ioa_ratio` | Most targeted IOA / total | 0-1 |
| `ioa_entropy` | Shannon entropy of IOA distribution | bits |
| `interrogation_count` | C_IC_NA_1 commands | count |
| `event_burstiness` | Ratio of events in short bursts | 0-1 |
| `unexpected_cot_sequence` | COT transitions violating protocol | count |

Run `python simulate_stages.py --output-dir output` to generate complete feature vectors across all 8 stages.

## IEC-104 Frame Generation

The simulator builds raw IEC-104 APDU/ASDU frames in pure Python (no libpcap dependency):

- **I-frames**: Information transfer with sequence numbers, TypeID, COT, Common Address, IOA
- **U-frames**: Link management (STARTDT, STOPDT, TESTFR)
- **PCAP output**: Minimal Ethernet/IP/TCP encapsulation for Wireshark compatibility

Supported ASDU types:
- `C_IC_NA_1` (100) -- General Interrogation
- `C_RD_NA_1` (102) -- Read Command
- `C_SC_NA_1` (45) -- Single Command
- `C_DC_NA_1` (46) -- Double Command
- `C_SE_NA_1` (48) -- Set-Point Normalized
- `M_SP_NA_1` (1) -- Single-Point Information (response)
- `M_ME_NA_1` (9) -- Measured Value Normalized (response)

## Stealth Attack Simulation

`simulate_stealth_attacks.py` generates 5 low-and-slow attack scenarios designed to test the limits of ML-based anomaly detection. Unlike the 8-stage generator which produces overtly anomalous traffic, these scenarios keep individual feature values within 1-2 standard deviations of normal baselines.

### 5 Stealth Scenarios

| Scenario | Windows | Strategy | MITRE | Detection Challenge |
|----------|---------|----------|-------|---------------------|
| `slow_drip` | 24 (72h) | 1 command per 3h window | T0855 | Below threshold in any single window |
| `exfiltration` | 48 | Bytes increase by 0.1 std/window | T0802 | Gradual drift stays under mean+1.5std |
| `living_off_the_land` | 20 | Legitimate TypeIDs, subtle COT violations | T0836 | Uses normal protocol operations |
| `time_shift` | 16 | Normal patterns at 02:00-04:00 | T0820 | Temporal features only signal |
| `recon_masquerade` | 12 | 1 interrogation/window, distributed | T0846 | No single window shows concentration |

### Usage

```bash
# Generate all 5 stealth scenarios
python simulate_stealth_attacks.py --output-dir output

# Generate specific scenarios
python simulate_stealth_attacks.py --scenario slow_drip,exfiltration --output-dir output

# Feature vectors only (combined JSON)
python simulate_stealth_attacks.py --features-only --output-dir output
```

### Output

```
output/
  slow_drip_features.json           # Per-window feature vectors
  exfiltration_features.json
  living_off_the_land_features.json
  time_shift_features.json
  recon_masquerade_features.json
  stealth_features.json             # Combined: all scenarios + baseline stats
```

These scenarios validate that single-window unsupervised anomaly detection models struggle with stealth attacks that stay within normal statistical bounds -- a known limitation that motivates complementary detection strategies such as cross-window risk accumulation, protocol sequence analysis, and IP-pair behavioral profiling.

## References

- [MITRE ATT&CK for ICS](https://attack.mitre.org/techniques/ics/) -- Technique mappings
- [IEC 60870-5-104](https://webstore.iec.ch/en/publication/3737) -- Protocol specification
- [ESET Industroyer2 Analysis](https://www.welivesecurity.com/2022/04/12/industroyer2-industroyer-reloaded/) -- Real-world IEC-104 attack
- [Cisco Talos IEC-104 Rules](https://www.snort.org/) -- SIDs 41053-41077

## License

This project is released for academic and defensive cybersecurity research purposes. The generated PCAPs contain simulated attack traffic and should only be used in controlled environments.
