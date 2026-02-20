#!/usr/bin/env python3
"""
5-Scenario Stealth Attack Simulator for IEC 60870-5-104.

Generates synthetic IEC-104 feature vectors that simulate low-and-slow attacks
designed to evade single-window anomaly detection. Unlike the 8-stage overt
attack generator, these scenarios keep individual feature values within 1-2
standard deviations of normal baselines.

Scenarios:
  1. Slow Drip Command Injection — 1 command per 3h window over 72h
  2. Low and Slow Data Exfiltration — gradual bytes increase over 48 windows
  3. Living off the Land Protocol Abuse — legitimate TypeIDs with subtle COT violations
  4. Time Shift Attack — normal patterns replayed at unusual hours
  5. Reconnaissance Masquerade — distributed interrogation across 12 windows

Output:
  stealth_features.json — feature vectors for all 5 scenarios

Usage:
    python simulate_stealth_attacks.py --output-dir output
    python simulate_stealth_attacks.py --scenario slow_drip --output-dir output
    python simulate_stealth_attacks.py --features-only
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Normal IEC-104 baseline statistics (derived from operational SCADA traffic)
# These represent typical 60-second window feature values for legitimate
# IEC-104 communication between an HMI/SCADA master and RTU/substation.
# ---------------------------------------------------------------------------

NORMAL_BASELINE: dict[str, dict[str, float]] = {
    "n_flows": {"mean": 2.5, "std": 1.2},
    "total_bytes": {"mean": 2600.0, "std": 1200.0},
    "total_pkts": {"mean": 45.0, "std": 20.0},
    "mean_duration": {"mean": 55.0, "std": 10.0},
    "n_events": {"mean": 210.0, "std": 220.0},
    "unique_typeIDs": {"mean": 4.0, "std": 2.0},
    "unique_cots": {"mean": 3.0, "std": 1.5},
    "unique_ioas": {"mean": 20.0, "std": 20.0},
    "mean_asdu_length": {"mean": 14.0, "std": 3.0},
    "events_per_second": {"mean": 3.5, "std": 3.7},
    "command_vs_monitor_ratio": {"mean": 0.02, "std": 0.05},
    "interrogation_count": {"mean": 0.1, "std": 0.3},
    "command_rate": {"mean": 0.44, "std": 0.35},
    "orig_event_ratio": {"mean": 0.15, "std": 0.10},
    "dominant_type_ratio": {"mean": 0.6, "std": 0.2},
    "dominant_ioa_ratio": {"mean": 0.15, "std": 0.10},
    "ioa_entropy": {"mean": 3.0, "std": 1.5},
    "unique_common_addresses": {"mean": 1.2, "std": 0.5},
    "mean_nobj": {"mean": 1.5, "std": 0.8},
    "unique_originators": {"mean": 1.0, "std": 0.2},
    "s_frame_ratio": {"mean": 0.05, "std": 0.03},
    "orig_command_count": {"mean": 2.0, "std": 3.0},
    "typeid_bigram_entropy": {"mean": 1.5, "std": 0.8},
    "delta_n_events_ratio": {"mean": 1.0, "std": 0.5},
    "rolling_zscore_n_events": {"mean": 0.0, "std": 1.0},
    "self_baseline_bytes_zscore": {"mean": 0.0, "std": 1.0},
    "delta_events_per_second": {"mean": 0.0, "std": 0.5},
}

# IEC-104 feature names used in the output vectors
IEC104_FEATURES = [
    "n_events", "unique_typeIDs", "unique_cots", "unique_ioas",
    "mean_asdu_length", "events_per_second", "command_vs_monitor_ratio",
    "interrogation_count", "command_rate", "orig_event_ratio",
    "dominant_type_ratio", "dominant_ioa_ratio", "ioa_entropy",
    "unique_common_addresses", "mean_nobj", "unique_originators",
    "s_frame_ratio", "orig_command_count",
]

# Network-level features
NETWORK_FEATURES = [
    "n_flows", "total_bytes", "total_pkts", "mean_duration",
]

# Temporal/behavioral features
TEMPORAL_FEATURES = [
    "delta_n_events_ratio", "rolling_zscore_n_events",
    "self_baseline_bytes_zscore", "delta_events_per_second",
]

# Scenario names
SCENARIO_NAMES = [
    "slow_drip",
    "exfiltration",
    "living_off_the_land",
    "time_shift",
    "recon_masquerade",
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class StealthWindow:
    """A single window in a stealth attack scenario."""

    window_index: int
    is_attack: bool
    features: dict[str, float]
    description: str = ""


@dataclass
class StealthScenario:
    """Complete stealth attack scenario with metadata."""

    name: str
    description: str
    mitre_technique: str
    mitre_tactic: str
    total_windows: int
    attack_windows: int
    windows: list[StealthWindow] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-safe dict."""
        return {
            "scenario": self.name,
            "description": self.description,
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic,
            "total_windows": self.total_windows,
            "attack_windows": self.attack_windows,
            "windows": [
                {
                    "window_index": w.window_index,
                    "is_attack": w.is_attack,
                    "description": w.description,
                    "features": w.features,
                }
                for w in self.windows
            ],
        }


# ---------------------------------------------------------------------------
# Helper: generate normal baseline window
# ---------------------------------------------------------------------------


def _normal_window() -> dict[str, float]:
    """Generate a feature dict representing a normal IEC-104 window.

    Values are drawn from the baseline means (deterministic for
    reproducibility — no random noise added).
    """
    features: dict[str, float] = {}
    for feat in IEC104_FEATURES + NETWORK_FEATURES + TEMPORAL_FEATURES:
        stats = NORMAL_BASELINE.get(feat, {"mean": 0.0})
        features[feat] = stats["mean"]
    # Behavioral flags
    features["command_without_interrogation"] = 0.0
    features["unexpected_cot_sequence"] = 0.0
    features["event_burstiness"] = 0.0
    return features


def _get_stat(name: str, field: str = "mean") -> float:
    """Get a baseline statistic value."""
    return NORMAL_BASELINE.get(name, {"mean": 0.0, "std": 1.0}).get(field, 0.0)


# ---------------------------------------------------------------------------
# Scenario generators
# ---------------------------------------------------------------------------


def scenario_slow_drip() -> StealthScenario:
    """Scenario 1: Slow Drip Command Injection.

    24 windows (72h at 3h intervals). Every 3rd window has 1 extra command
    injected. All features stay within 1 std of normal.
    """
    scenario = StealthScenario(
        name="slow_drip",
        description="24 windows (72h @ 3h intervals), 1 command injected every 3rd window",
        mitre_technique="T0855",
        mitre_tactic="Impair Process Control",
        total_windows=24,
        attack_windows=8,
    )

    for i in range(24):
        feats = _normal_window()
        is_attack = (i % 3 == 1)

        if is_attack:
            feats["orig_command_count"] = feats["orig_command_count"] + 1.0
            feats["command_rate"] = 1.0 / 3600.0  # 1 cmd per 3h window
            feats["n_events"] = feats["n_events"] + 1.0
            feats["command_vs_monitor_ratio"] = max(feats["command_vs_monitor_ratio"], 0.001)
            feats["orig_event_ratio"] = min(
                feats["orig_event_ratio"] + 1.0 / max(feats["n_events"], 1.0), 1.0,
            )
            desc = "Normal + 1 injected command"
        else:
            desc = "Normal filler window"

        scenario.windows.append(StealthWindow(
            window_index=i, is_attack=is_attack, features=feats, description=desc,
        ))

    return scenario


def scenario_exfiltration() -> StealthScenario:
    """Scenario 2: Low and Slow Data Exfiltration.

    48 windows. Bytes increase gradually, capped at mean + 1.5*std so no
    single window is extreme. IEC-104 features stay normal.
    """
    scenario = StealthScenario(
        name="exfiltration",
        description="48 windows with gradually increasing total_bytes (capped at mean+1.5*std)",
        mitre_technique="T0802",
        mitre_tactic="Collection",
        total_windows=48,
        attack_windows=48,
    )

    bytes_mean = _get_stat("total_bytes", "mean")
    bytes_std = _get_stat("total_bytes", "std")
    cap = bytes_mean + 1.5 * bytes_std

    for i in range(48):
        feats = _normal_window()
        added = (0.2 + 0.1 * i) * bytes_std
        feats["total_bytes"] = min(bytes_mean + added, cap)

        scenario.windows.append(StealthWindow(
            window_index=i, is_attack=True, features=feats,
            description=f"Bytes: {feats['total_bytes']:.0f} (normal mean={bytes_mean:.0f})",
        ))

    return scenario


def scenario_living_off_the_land() -> StealthScenario:
    """Scenario 3: Living off the Land Protocol Abuse.

    20 windows using legitimate TypeIDs and normal event rates but with
    command_without_interrogation=1 and unexpected_cot_sequence=1.
    unique_ioas slightly elevated (+1 std).
    """
    scenario = StealthScenario(
        name="living_off_the_land",
        description="20 windows with legitimate TypeIDs, subtle COT violations",
        mitre_technique="T0836",
        mitre_tactic="Impair Process Control",
        total_windows=20,
        attack_windows=20,
    )

    ioas_target = _get_stat("unique_ioas") + _get_stat("unique_ioas", "std")

    for i in range(20):
        feats = _normal_window()
        feats["command_without_interrogation"] = 1.0
        feats["unexpected_cot_sequence"] = 1.0
        feats["unique_ioas"] = ioas_target
        # Keep rates exactly at normal means
        feats["events_per_second"] = _get_stat("events_per_second")
        feats["command_rate"] = _get_stat("command_rate")
        feats["n_events"] = _get_stat("n_events")

        scenario.windows.append(StealthWindow(
            window_index=i, is_attack=True, features=feats,
            description="Normal ops with COT violation flags",
        ))

    return scenario


def scenario_time_shift() -> StealthScenario:
    """Scenario 4: Time Shift Attack.

    16 windows with normal IEC-104 patterns but elevated temporal delta
    features, simulating legitimate traffic replayed at 02:00-04:00.
    """
    scenario = StealthScenario(
        name="time_shift",
        description="16 windows with elevated temporal deltas (off-hours replay at 02:00-04:00)",
        mitre_technique="T0820",
        mitre_tactic="Evasion",
        total_windows=16,
        attack_windows=16,
    )

    eps_mean = _get_stat("events_per_second")

    for i in range(16):
        feats = _normal_window()
        feats["delta_n_events_ratio"] = 5.0  # traffic suddenly appears at quiet time
        feats["rolling_zscore_n_events"] = 3.0  # count deviates from recent history
        feats["self_baseline_bytes_zscore"] = 2.5  # unusual bytes for this hour
        feats["delta_events_per_second"] = eps_mean * 0.8  # change from quiescent

        scenario.windows.append(StealthWindow(
            window_index=i, is_attack=True, features=feats,
            description="Normal IEC-104 at unusual hour (02:00-04:00)",
        ))

    return scenario


def scenario_recon_masquerade() -> StealthScenario:
    """Scenario 5: Reconnaissance Masquerade.

    12 windows, each with 1 interrogation, slightly elevated unique_ioas
    (+2), and slightly elevated entropy. No single window is extreme.
    """
    scenario = StealthScenario(
        name="recon_masquerade",
        description="12 windows with 1 interrogation each, distributed reconnaissance",
        mitre_technique="T0846",
        mitre_tactic="Discovery",
        total_windows=12,
        attack_windows=12,
    )

    ioas_target = _get_stat("unique_ioas") + 2.0
    bigram_target = _get_stat("typeid_bigram_entropy") + 0.5 * _get_stat("typeid_bigram_entropy", "std")
    ioa_ent_target = _get_stat("ioa_entropy") + 0.5 * _get_stat("ioa_entropy", "std")

    for i in range(12):
        feats = _normal_window()
        feats["interrogation_count"] = 1.0
        feats["unique_ioas"] = ioas_target
        feats["events_per_second"] = _get_stat("events_per_second")
        feats["typeid_bigram_entropy"] = bigram_target
        feats["ioa_entropy"] = ioa_ent_target

        scenario.windows.append(StealthWindow(
            window_index=i, is_attack=True, features=feats,
            description=f"1 interrogation, {ioas_target:.0f} IOAs",
        ))

    return scenario


# ---------------------------------------------------------------------------
# Scenario registry
# ---------------------------------------------------------------------------

SCENARIO_GENERATORS = {
    "slow_drip": scenario_slow_drip,
    "exfiltration": scenario_exfiltration,
    "living_off_the_land": scenario_living_off_the_land,
    "time_shift": scenario_time_shift,
    "recon_masquerade": scenario_recon_masquerade,
}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def run_scenarios(
    scenario_names: list[str],
    output_dir: Path,
    features_only: bool = False,
) -> list[StealthScenario]:
    """Generate stealth attack scenarios and save outputs.

    Args:
        scenario_names: List of scenario names to generate.
        output_dir: Directory for output files.
        features_only: If True, only output the combined JSON (no per-scenario files).

    Returns:
        List of generated StealthScenario objects.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    scenarios: list[StealthScenario] = []

    for name in scenario_names:
        if name not in SCENARIO_GENERATORS:
            logger.warning("Unknown scenario: %s (skipping)", name)
            continue

        gen_fn = SCENARIO_GENERATORS[name]
        scenario = gen_fn()
        scenarios.append(scenario)

        logger.info(
            "Scenario '%s': %d total windows, %d attack windows",
            scenario.name, scenario.total_windows, scenario.attack_windows,
        )

        if not features_only:
            # Save per-scenario JSON
            report_path = output_dir / f"{name}_features.json"
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(scenario.to_dict(), f, indent=2)
            logger.info("Saved %s", report_path)

    # Save combined features
    combined = {
        "generator": "IEC-104 Stealth Attack Simulator",
        "scenarios": [s.to_dict() for s in scenarios],
        "baseline_statistics": NORMAL_BASELINE,
        "feature_list": {
            "iec104": IEC104_FEATURES,
            "network": NETWORK_FEATURES,
            "temporal": TEMPORAL_FEATURES,
        },
    }
    combined_path = output_dir / "stealth_features.json"
    with open(combined_path, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2)
    logger.info("Combined features saved to %s", combined_path)

    # Print summary
    print(f"\n{'='*70}")
    print("STEALTH ATTACK SCENARIO SUMMARY")
    print(f"{'='*70}")
    print(f"{'Scenario':<25} {'Windows':<10} {'Attack':<10} {'MITRE':<10} {'Tactic'}")
    print(f"{'-'*70}")
    for s in scenarios:
        print(
            f"{s.name:<25} {s.total_windows:<10} {s.attack_windows:<10} "
            f"{s.mitre_technique:<10} {s.mitre_tactic}"
        )
    print(f"{'='*70}")
    print(f"Output: {output_dir}")

    return scenarios


def main() -> None:
    """Entry point."""
    parser = argparse.ArgumentParser(
        description="IEC-104 Stealth Attack Feature Vector Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Scenarios:\n"
            "  slow_drip           - Single command injection at 3h intervals (72h)\n"
            "  exfiltration        - Gradual bytes increase over 48 windows\n"
            "  living_off_the_land - Legitimate TypeIDs with subtle COT violations\n"
            "  time_shift          - Normal patterns replayed at unusual hours\n"
            "  recon_masquerade    - Distributed interrogation across 12 windows\n"
            "\n"
            "Examples:\n"
            "  python simulate_stealth_attacks.py --output-dir output\n"
            "  python simulate_stealth_attacks.py --scenario slow_drip,exfiltration\n"
            "  python simulate_stealth_attacks.py --features-only\n"
        ),
    )
    parser.add_argument(
        "--scenario", type=str, default="all",
        help="Comma-separated scenario names or 'all' (default: all)",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("output"),
        help="Output directory (default: output/)",
    )
    parser.add_argument(
        "--features-only", action="store_true",
        help="Only output combined JSON (no per-scenario files)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose logging",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.scenario.strip().lower() == "all":
        names = list(SCENARIO_NAMES)
    else:
        names = [s.strip() for s in args.scenario.split(",") if s.strip()]

    if not names:
        logger.error("No valid scenarios specified")
        sys.exit(1)

    run_scenarios(names, args.output_dir, features_only=args.features_only)


if __name__ == "__main__":
    main()
