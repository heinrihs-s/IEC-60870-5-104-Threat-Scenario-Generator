#!/usr/bin/env python3
"""
Synthetic attack feature-space generator for offline evaluation.

Generates realistic attack-like feature perturbations for stress-testing
the anomaly detection pipeline. All attacks are synthetic, clearly marked,
and operate in feature space (not packet space).

Attack families:
  1. Reconnaissance / Discovery: port scans, service enumeration
  2. Collection / Monitoring: excessive polling, new IOA queries
  3. C2-like: unusual communication patterns, timing anomalies
  4. Brute-force I/O: high-rate commands, IOA flooding
  5. Parameter modification: write commands to unusual targets
  6. Stealth variants: low-and-slow, context-preserving, distributed
  7. Protocol-identical: behaviorally suspicious but spec-compliant
"""

import logging
import math
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


def _sample_baseline_windows(
    df: pd.DataFrame, n: int = 100, seed: int = 42
) -> pd.DataFrame:
    """Sample baseline normal windows for perturbation."""
    rng = np.random.RandomState(seed)
    idx = rng.choice(len(df), size=min(n, len(df)), replace=False)
    return df.iloc[idx].copy().reset_index(drop=True)


def generate_reconnaissance(
    df: pd.DataFrame, n: int = 50, seed: int = 42
) -> pd.DataFrame:
    """Reconnaissance: unusual port scanning, service enumeration."""
    rng = np.random.RandomState(seed)
    samples = _sample_baseline_windows(df, n, seed)

    # Increase unique destination ports and connection attempts
    samples["unique_dst_ports"] = samples["unique_dst_ports"] * rng.uniform(3, 10, n)
    samples["n_flows"] = samples["n_flows"] * rng.uniform(2, 5, n)
    samples["conn_state_S0"] = samples["conn_state_S0"] + rng.uniform(5, 30, n)
    samples["conn_state_REJ"] = samples["conn_state_REJ"] + rng.uniform(2, 15, n)
    samples["conn_state_SF"] = np.maximum(samples["conn_state_SF"] - 5, 0)
    samples["bytes_ratio"] = rng.uniform(0.8, 1.2, n)  # Nearly symmetric (probes)

    samples["_attack_family"] = "reconnaissance"
    samples["_attack_type"] = "port_scan"
    samples["_attack_difficulty"] = "easy"
    return samples


def generate_collection(
    df: pd.DataFrame, n: int = 50, seed: int = 42
) -> pd.DataFrame:
    """Collection: excessive polling, reading many IOAs."""
    rng = np.random.RandomState(seed)
    iec_mask = df.get("has_iec104_traffic", pd.Series(dtype=float)).fillna(0) > 0
    if iec_mask.sum() < 10:
        iec_mask = pd.Series([True] * len(df))

    iec_df = df[iec_mask]
    samples = _sample_baseline_windows(iec_df, n, seed)

    # Excessive interrogation and IOA reads
    samples["interrogation_count"] = samples.get("interrogation_count", 0) + rng.randint(3, 15, n)
    samples["unique_ioas"] = samples.get("unique_ioas", 0) * rng.uniform(2, 8, n)
    samples["n_events"] = samples.get("n_events", 0) * rng.uniform(3, 10, n)
    samples["events_per_second"] = samples.get("events_per_second", 0) * rng.uniform(2, 5, n)
    samples["command_vs_monitor_ratio"] = rng.uniform(0, 0.1, n)  # Mostly reading

    samples["_attack_family"] = "collection"
    samples["_attack_type"] = "excessive_polling"
    samples["_attack_difficulty"] = "easy"
    return samples


def generate_c2_pattern(
    df: pd.DataFrame, n: int = 50, seed: int = 42
) -> pd.DataFrame:
    """C2-like: unusual timing regularity, beaconing patterns."""
    rng = np.random.RandomState(seed)
    samples = _sample_baseline_windows(df, n, seed)

    # High regularity (beaconing)
    if "iat_cv" in samples.columns:
        samples["iat_cv"] = rng.uniform(0.01, 0.1, n)  # Very regular IAT
    if "event_regularity" in samples.columns:
        samples["event_regularity"] = rng.uniform(0.8, 0.99, n)
    if "iat_mean" in samples.columns:
        samples["iat_mean"] = rng.choice([1.0, 5.0, 10.0, 30.0, 60.0], n)  # Fixed intervals

    # Moderate but persistent traffic
    samples["n_flows"] = rng.uniform(5, 20, n)
    samples["total_bytes"] = rng.uniform(100, 2000, n)

    samples["_attack_family"] = "c2"
    samples["_attack_type"] = "beaconing"
    samples["_attack_difficulty"] = "medium"
    return samples


def generate_brute_io(
    df: pd.DataFrame, n: int = 50, seed: int = 42
) -> pd.DataFrame:
    """Brute-force I/O: rapid command sequences to many IOAs."""
    rng = np.random.RandomState(seed)
    iec_mask = df.get("has_iec104_traffic", pd.Series(dtype=float)).fillna(0) > 0
    iec_df = df[iec_mask] if iec_mask.sum() >= 10 else df

    samples = _sample_baseline_windows(iec_df, n, seed)

    # Heavy command traffic
    samples["command_rate"] = rng.uniform(5, 50, n)
    samples["orig_command_count"] = rng.randint(10, 100, n)
    samples["command_vs_monitor_ratio"] = rng.uniform(0.5, 1.0, n)
    samples["orig_event_ratio"] = rng.uniform(0.6, 1.0, n)
    samples["n_events"] = rng.randint(50, 500, n)
    samples["unique_ioas"] = rng.randint(10, 100, n)
    samples["dominant_ioa_ratio"] = rng.uniform(0.01, 0.15, n)  # Spread across many IOAs
    samples["ioa_entropy"] = rng.uniform(3, 6, n)

    samples["_attack_family"] = "brute_io"
    samples["_attack_type"] = "command_flood"
    samples["_attack_difficulty"] = "easy"
    return samples


def generate_parameter_modification(
    df: pd.DataFrame, n: int = 50, seed: int = 42
) -> pd.DataFrame:
    """Parameter modification: write commands to unusual targets."""
    rng = np.random.RandomState(seed)
    iec_mask = df.get("has_iec104_traffic", pd.Series(dtype=float)).fillna(0) > 0
    iec_df = df[iec_mask] if iec_mask.sum() >= 10 else df

    samples = _sample_baseline_windows(iec_df, n, seed)

    # Moderate commands but unusual types
    samples["command_rate"] = rng.uniform(0.5, 5, n)
    samples["orig_command_count"] = rng.randint(2, 20, n)
    samples["command_vs_monitor_ratio"] = rng.uniform(0.3, 0.8, n)
    samples["dominant_type_ratio"] = rng.uniform(0.6, 0.95, n)  # Concentrated on write types
    samples["unique_typeIDs"] = rng.randint(1, 4, n)  # Few types (setpoint writes)
    samples["cot_entropy"] = rng.uniform(0.3, 1.0, n)

    samples["_attack_family"] = "modification"
    samples["_attack_type"] = "parameter_change"
    samples["_attack_difficulty"] = "medium"
    return samples


def generate_stealth_slow_drip(
    df: pd.DataFrame, n: int = 100, seed: int = 42
) -> pd.DataFrame:
    """Stealth: low-and-slow distributed behavior across many windows."""
    rng = np.random.RandomState(seed)
    samples = _sample_baseline_windows(df, n, seed)

    # Very subtle perturbations
    for feat in ["n_flows", "total_bytes", "n_events"]:
        if feat in samples.columns:
            noise = rng.normal(1.0, 0.15, n)  # +/- 15%
            samples[feat] = samples[feat] * np.maximum(noise, 0.1)

    # Slight increase in command activity
    if "command_rate" in samples.columns:
        samples["command_rate"] = samples["command_rate"] + rng.uniform(0.1, 0.5, n)
    if "orig_command_count" in samples.columns:
        samples["orig_command_count"] = samples["orig_command_count"] + rng.randint(0, 3, n)

    # Subtle timing anomaly
    if "iat_cv" in samples.columns:
        samples["iat_cv"] = samples["iat_cv"] * rng.uniform(0.7, 1.3, n)

    samples["_attack_family"] = "stealth"
    samples["_attack_type"] = "slow_drip"
    samples["_attack_difficulty"] = "hard"
    return samples


def generate_context_preserving(
    df: pd.DataFrame, n: int = 50, seed: int = 42
) -> pd.DataFrame:
    """Context-preserving: protocol-compliant but contextually wrong."""
    rng = np.random.RandomState(seed)
    iec_mask = df.get("has_iec104_traffic", pd.Series(dtype=float)).fillna(0) > 0
    iec_df = df[iec_mask] if iec_mask.sum() >= 10 else df

    samples = _sample_baseline_windows(iec_df, n, seed)

    # Shift timing to wrong hour (but keep everything else normal)
    # Simulate commands at unusual hours by perturbing temporal features
    if "rolling_zscore_command_rate" in samples.columns:
        samples["rolling_zscore_command_rate"] = rng.uniform(2, 5, n)
    if "self_baseline_bytes_zscore" in samples.columns:
        samples["self_baseline_bytes_zscore"] = rng.uniform(1.5, 4, n)

    # Normal protocol behavior but unusual sequence patterns
    if "typeid_bigram_entropy" in samples.columns:
        samples["typeid_bigram_entropy"] = samples["typeid_bigram_entropy"] * rng.uniform(0.3, 0.6, n)
    if "unexpected_cot_sequence" in samples.columns:
        samples["unexpected_cot_sequence"] = rng.randint(1, 5, n)

    samples["_attack_family"] = "context_preserving"
    samples["_attack_type"] = "wrong_context"
    samples["_attack_difficulty"] = "hard"
    return samples


def generate_weekend_masquerade(
    df: pd.DataFrame, n: int = 30, seed: int = 42
) -> pd.DataFrame:
    """Attack hidden in weekend-like low-activity periods."""
    rng = np.random.RandomState(seed)

    # Use weekend windows as baseline
    if "is_weekend" in df.columns:
        weekend_df = df[df["is_weekend"] == 1]
        if len(weekend_df) < 10:
            weekend_df = df
    else:
        weekend_df = df

    samples = _sample_baseline_windows(weekend_df, n, seed)

    # Add subtle anomalous IEC-104 activity during quiet periods
    if "n_events" in samples.columns:
        samples["n_events"] = samples["n_events"] + rng.randint(5, 30, n)
    if "command_rate" in samples.columns:
        samples["command_rate"] = rng.uniform(0.5, 3, n)
    if "orig_command_count" in samples.columns:
        samples["orig_command_count"] = rng.randint(1, 10, n)

    samples["_attack_family"] = "masquerade"
    samples["_attack_type"] = "weekend_hidden"
    samples["_attack_difficulty"] = "hard"
    return samples


def generate_all_attacks(
    df: pd.DataFrame, n_per_family: int = 50, seed: int = 42
) -> pd.DataFrame:
    """Generate all synthetic attack families.

    Returns DataFrame with attack meta columns:
        _attack_family, _attack_type, _attack_difficulty, _is_synthetic
    """
    generators = [
        generate_reconnaissance,
        generate_collection,
        generate_c2_pattern,
        generate_brute_io,
        generate_parameter_modification,
        generate_stealth_slow_drip,
        generate_context_preserving,
        generate_weekend_masquerade,
    ]

    all_attacks = []
    for i, gen in enumerate(generators):
        try:
            attacks = gen(df, n=n_per_family, seed=seed + i)
            attacks["_is_synthetic"] = True
            attacks["_label"] = 1  # Attack
            all_attacks.append(attacks)
            logger.info(
                "Generated %d %s attacks (%s)",
                len(attacks),
                attacks["_attack_family"].iloc[0],
                attacks["_attack_difficulty"].iloc[0],
            )
        except Exception as e:
            logger.warning("Failed to generate %s: %s", gen.__name__, e)

    if not all_attacks:
        return pd.DataFrame()

    combined = pd.concat(all_attacks, ignore_index=True)
    logger.info("Total synthetic attacks: %d across %d families", len(combined), len(all_attacks))
    return combined


def evaluate_detection(
    normal_df: pd.DataFrame,
    attack_df: pd.DataFrame,
    score_fn,
    feature_columns: list[str],
) -> dict[str, Any]:
    """Evaluate detector against normal + synthetic attacks.

    Args:
        normal_df: Normal baseline windows.
        attack_df: Synthetic attack windows.
        score_fn: Function(DataFrame) -> np.ndarray of anomaly scores.
        feature_columns: Feature columns to use.

    Returns:
        Evaluation metrics per attack family.
    """
    from sklearn.metrics import roc_auc_score, precision_recall_curve, auc

    # Score normal
    normal_scores = score_fn(normal_df)
    normal_df = normal_df.copy()
    normal_df["_score"] = normal_scores
    normal_df["_label"] = 0

    results = {"n_normal": len(normal_df), "families": {}}

    # Score each attack family separately
    families = attack_df["_attack_family"].unique() if "_attack_family" in attack_df.columns else ["all"]

    for family in families:
        fam_mask = attack_df["_attack_family"] == family if "_attack_family" in attack_df.columns else pd.Series([True] * len(attack_df))
        fam_df = attack_df[fam_mask].copy()

        try:
            fam_scores = score_fn(fam_df)
            fam_df["_score"] = fam_scores

            # Combine for metrics
            all_labels = np.concatenate([
                np.zeros(len(normal_df)),
                np.ones(len(fam_df)),
            ])
            all_scores = np.concatenate([normal_scores, fam_scores])

            roc_auc = float(roc_auc_score(all_labels, all_scores))
            precision, recall, _ = precision_recall_curve(all_labels, all_scores)
            pr_auc = float(auc(recall, precision))

            # Detection rates at key thresholds
            p95 = float(np.percentile(normal_scores, 95))
            p99 = float(np.percentile(normal_scores, 99))

            det_p95 = float((fam_scores > p95).mean())
            det_p99 = float((fam_scores > p99).mean())

            difficulty = str(fam_df["_attack_difficulty"].iloc[0]) if "_attack_difficulty" in fam_df.columns else "unknown"

            results["families"][family] = {
                "n_samples": int(len(fam_df)),
                "difficulty": difficulty,
                "roc_auc": roc_auc,
                "pr_auc": pr_auc,
                "detection_rate_p95": det_p95,
                "detection_rate_p99": det_p99,
                "mean_score": float(np.mean(fam_scores)),
                "max_score": float(np.max(fam_scores)),
                "normal_p95_threshold": float(p95),
                "normal_p99_threshold": float(p99),
            }

        except Exception as e:
            logger.warning("Failed to evaluate %s: %s", family, e)
            results["families"][family] = {"error": str(e)}

    return results
