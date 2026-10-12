"""
Lab 3 - Task 2: Windows Agent Context Governance Benchmark
File: easy_agent_benchmark.py
Description: Evaluates Dirty Sandbox vs. Clean v1 (SHA-256) vs. Clean v2 (HMAC+).
             Evaluates baseline 'my_custom_contexts.json' first.
             Optional: pass '--extra <file.json>' to evaluate custom context items.
Dependencies: Python standard library only.
"""

import os
import json
import time
import hmac
import hashlib
import re
import argparse

GATEWAY_KEY = b"uts-student-lab-demo-key-2026"
MAX_AGE_SECONDS = 3600

DIRTY_TRIGGER = re.compile(
    r"(ignore|forget)( all)? previous instructions"
    r"|system override"
    r"|exfiltrate"
    r"|defamatory"
    r"|PROMPTBENCH_OVERRIDE",
    re.IGNORECASE
)

CLEAN_V2_TRIGGER = re.compile(
    r"(ignore|forget)( all)? previous instructions"
    r"|system override"
    r"|exfiltrate"
    r"|defamatory"
    r"|password"
    r"|PROMPTBENCH_OVERRIDE",
    re.IGNORECASE
)


def _serialize(text: str, uri: str, timestamp: int) -> bytes:
    return f"{text}|{uri}|{timestamp}".encode("utf-8")


def plain_sha256(text: str, uri: str, timestamp: int) -> str:
    return hashlib.sha256(_serialize(text, uri, timestamp)).hexdigest()


def hmac_sha256(text: str, uri: str, timestamp: int) -> str:
    return hmac.new(GATEWAY_KEY, _serialize(text, uri, timestamp), hashlib.sha256).hexdigest()


def gateway_wrap(text: str, uri: str, timestamp: int) -> dict:
    return {
        "text": text,
        "uri": uri,
        "timestamp": timestamp,
        "sha256": plain_sha256(text, uri, timestamp),
        "hmac": hmac_sha256(text, uri, timestamp)
    }


def simulate_tamper(ctx: dict, tampered: str) -> dict:
    c = dict(ctx)
    c["text"] = tampered
    c["sha256"] = plain_sha256(tampered, c["uri"], c["timestamp"])
    return c


def run_dirty_sandbox(ctx: dict, now: int):
    if DIRTY_TRIGGER.search(ctx["text"]):
        return "COMPROMISED", f"Agent executed instruction from '{ctx['uri']}'"
    return "SAFE", "Context ingested normally."


def run_clean_v1(ctx: dict, now: int):
    if plain_sha256(ctx["text"], ctx["uri"], ctx["timestamp"]) != ctx["sha256"]:
        return "QUARANTINED", "SHA-256 mismatch: in-flight corruption"
    if not ctx["uri"].startswith("internal://"):
        return "QUARANTINED", f"Untrusted origin URI: '{ctx['uri']}'"
    return "SAFE", "Passed v1"


def run_clean_v2(ctx: dict, now: int):
    expected_hmac = hmac_sha256(ctx["text"], ctx["uri"], ctx["timestamp"])
    if not hmac.compare_digest(expected_hmac, ctx["hmac"]):
        return "QUARANTINED", "HMAC mismatch: content altered after signing"

    if not ctx["uri"].startswith("internal://"):
        return "QUARANTINED", f"Untrusted origin URI: '{ctx['uri']}'"

    age = now - ctx["timestamp"]
    if age > MAX_AGE_SECONDS:
        return "QUARANTINED", f"Stale context: age {age}s exceeds {MAX_AGE_SECONDS}s"

    if CLEAN_V2_TRIGGER.search(ctx["text"]):
        return "QUARANTINED", "Injection pattern detected by rule"

    return "SAFE", "Passed v2"


MODES = [
    ("Dirty Sandbox ", run_dirty_sandbox),
    ("Clean v1 (SHA)", run_clean_v1),
    ("Clean v2 (HMAC)", run_clean_v2)
]


def evaluate_dataset(dataset: list, now: int, title: str) -> dict:
    stats = {
        name: {"stopped": 0, "atk": 0, "fp": 0, "ben": 0}
        for name, _ in MODES
    }

    print("\n" + "=" * 76)
    print(f" {title} ({len(dataset)} items)")
    print("=" * 76)

    for idx, item in enumerate(dataset):
        required_keys = ("raw_text", "origin_uri", "expected_label")
        if any(k not in item for k in required_keys):
            print(f"[!] Skipping item #{idx}: Missing required fields.")
            continue

        cid = item.get("id", f"item_{idx}")
        scenario = item.get("scenario", "EVAL")
        label = str(item["expected_label"]).strip().upper()

        try:
            offset = int(item.get("timestamp_offset", 0))
        except (ValueError, TypeError):
            offset = 0

        ts = now - offset
        context_obj = gateway_wrap(item["raw_text"], item["origin_uri"], ts)

        if "tamper_after_sign" in item:
            context_obj = simulate_tamper(context_obj, item["tamper_after_sign"])

        is_attack = (label != "BENIGN")
        snippet = item["raw_text"][:60] + ("..." if len(item["raw_text"]) > 60 else "")

        print(f"\n[{cid}] Scenario: {scenario} | Expected: {label}")
        print(f"  URI: {context_obj['uri']}")
        print(f"  Raw: {snippet}")

        for mode_name, mode_func in MODES:
            status, msg = mode_func(context_obj, now)
            st = stats[mode_name]

            if is_attack:
                st["atk"] += 1
                if status == "QUARANTINED":
                    st["stopped"] += 1
            else:
                st["ben"] += 1
                if status == "QUARANTINED":
                    st["fp"] += 1

            print(f"  {mode_name:<16}: [{status:<11}] {msg}")

    print("\n" + "-" * 76)
    print(f" SCORECARD: {title}")
    print("-" * 76)
    for mode_name, st in stats.items():
        atk_stat = f"{st['stopped']}/{st['atk']}"
        fp_stat = f"{st['fp']}/{st['ben']}"
        fp_pct = (st['fp'] / st['ben'] * 100) if st['ben'] else 0.0
        print(f"  {mode_name:<16} | Attacks Stopped: {atk_stat:<5} | False Alarms: {fp_stat} ({fp_pct:.1f}%)")
    print("-" * 76)
    return stats


def main():
    parser = argparse.ArgumentParser(description="Agent Context Governance Benchmark")
    parser.add_argument("--baseline", type=str, default="my_custom_contexts.json",
                        help="Path to baseline JSON file")
    parser.add_argument("--extra", type=str, default=None,
                        help="Optional path to additional custom contexts JSON file")
    args = parser.parse_args()

    if not os.path.exists(args.baseline):
        print(f"[!] Error: Baseline file '{args.baseline}' not found.")
        return

    with open(args.baseline, "r", encoding="utf-8") as f:
        baseline_data = json.load(f)

    now = int(time.time())
    print("=" * 76)
    print(" AGENT CONTEXT GOVERNANCE BENCHMARK EVALUATOR")
    print(" Mode: Native Standard Library Execution (CPU / RAM)")
    print("=" * 76)

    baseline_stats = evaluate_dataset(baseline_data, now, "BASELINE EVALUATION")

    if baseline_stats["Clean v2 (HMAC)"]["fp"] > 0:
        print(f"[Observation Point]: Clean v2 produced {baseline_stats['Clean v2 (HMAC)']['fp']} false alarm(s).")
        print("Check ctx_07: Did benign context contain sensitive keywords like 'password'?")

    if args.extra:
        if not os.path.exists(args.extra):
            print(f"\n[!] Warning: Extra file '{args.extra}' not found.")
        else:
            with open(args.extra, "r", encoding="utf-8") as f:
                extra_data = json.load(f)
            evaluate_dataset(extra_data, now, "EXTRA / CUSTOM EVALUATION")


if __name__ == "__main__":
    main()