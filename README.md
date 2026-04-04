# IEC 60870-5-104 Threat Scenario Generator

Generates synthetic IEC 60870-5-104 (IEC-104) attack traffic for testing intrusion detection systems targeting SCADA/ICS environments. All traffic uses synthetic IP addresses and is safe for research and benchmarking.

## Scripts

### simulate_8_stages.py

8-stage attack scenario simulation based on MITRE ATT&CK for ICS:

| Stage | Technique | MITRE ID | Description |
|-------|-----------|----------|-------------|
| 1 | Remote System Discovery | T0888 | Interrogation sweep across 20 station addresses |
| 2 | Monitor Process State | T0801 | Frequent reads on 5 IOAs every 2s for 60s |
| 3 | Automated Collection | T0802 | Persistent polling loop: 50 IOAs every 3s |
| 4 | Command & Control | T0869 | Secondary TCP session with keepalives |
| 5 | Brute Force I/O | T0806 | IOA sweep: C_SC_NA_1 on 1,901 targets |
| 6 | Modify Parameter | T0836 | Setpoint changes on 5 critical IOAs |
| 7 | Unauthorized Command | T0855 | 10 command injections with invalid COT |
| 8 | Manipulation of Control | T0831 | Rapid contradictory open/close, 20 cycles |

```bash
python simulate_8_stages.py --output-dir output/sim_8stages
python simulate_8_stages.py --stage 7           # Single stage
python simulate_8_stages.py --features-only     # Feature vectors only
```

### generate_attack_pcaps.py

10 surgical attack PCAPs targeting specific detection blind spots:

| Attack | MITRE | Difficulty | Description |
|--------|-------|-----------|-------------|
| ATK-00 clean_baseline | N/A | control | Pure legitimate traffic (no attacks) |
| ATK-01 short_burst | T0831 | medium | 5x C_DC_NA_1 toggles in 15s |
| ATK-02 low_and_slow | T0836 | hard | 1 setpoint every 5min for 2h |
| ATK-03 topology_new_peer | T0846+T0855 | easy | Unseen IP opens connection |
| ATK-04 topology_lateral | T0812 | medium | HMI pivots to second RTU |
| ATK-05 legitimate_abuse | T0836 | hard | Protocol-compliant but contextually wrong |
| ATK-06 unseen_typeids | T0855+T0836 | medium | Novel TypeIDs (47, 110, 122) |
| ATK-07 partial_interrupted | T0855+T0814 | medium | Orphan commands, failed TESTFR |
| ATK-08 slow_toggle | T0831 | hard | ON/OFF every 10s, sub-threshold |
| ATK-09 chained_multi_stage | T0888+... | expert | 1-hour 4-phase kill chain |

```bash
python generate_attack_pcaps.py                        # All attacks
python generate_attack_pcaps.py --attack short_burst   # Single attack
python generate_attack_pcaps.py --list                 # List attacks
```

### generate_neg_confirm_pcap.py

Generates IEC-104 PCAPs with negative confirmation (P/N bit) for testing polarity detection:
- C_DC_NA_1 with ACTCON P/N=1 (command rejected)
- C_SE_NA_1 with ACTCON P/N=1 (setpoint rejected)
- Positive confirmation baseline for contrast

```bash
python generate_neg_confirm_pcap.py --output-dir output/pcaps
```

### synthetic_attacks.py

Feature-space synthetic attack generator (8 attack families) for offline evaluation of ML-based anomaly detectors. Operates on feature vectors, not packets.

Attack families: Reconnaissance, Collection, C2, Brute I/O, Parameter Modification, Stealth, Context-Preserving, Weekend Masquerade.

## Dependencies

- Python 3.10+
- numpy, pandas (for synthetic_attacks.py only)
- No external dependencies for PCAP generators (pure stdlib)


## License

MIT
