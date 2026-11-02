"""Empirical benchmark engine measuring Precision, Recall, and False Positive Rate.

Evaluates agent-redline against the labeled dataset in corpus/malicious.jsonl and corpus/benign.jsonl.
Provides strict verifiable numbers for documentation without synthetic claims.
"""

from __future__ import annotations

import json
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent_redline.config import load_config
from agent_redline.engine import Engine
from agent_redline.models import Decision, Mode, RedlineConfig, ToolCall, ToolKind


@dataclass(slots=True)
class BenchmarkResult:
    """Benchmark evaluation metrics."""

    total_evaluated: int
    malicious_count: int
    benign_count: int
    tp: int
    fn: int
    tn: int
    fp: int
    precision: float
    recall: float
    fpr: float
    accuracy: float
    mean_latency_ms: float
    p95_latency_ms: float
    missed_attacks: list[dict[str, Any]] = field(default_factory=list)
    false_positives: list[dict[str, Any]] = field(default_factory=list)

    def format_report(self) -> str:
        """Render a formatted ASCII benchmark card for terminal and documentation."""
        divider = "+" + "-" * 26 + "+" + "-" * 18 + "+"
        lines = [
            "",
            "===========================================================",
            "        agent-redline Security Benchmark Evaluation        ",
            "===========================================================",
            f" Total Evaluated Commands : {self.total_evaluated}",
            f" Malicious Test Samples   : {self.malicious_count}",
            f" Benign Developer Samples : {self.benign_count}",
            divider,
            f"| {'Metric':<24} | {'Measured Value':<16} |",
            divider,
            f"| {'Recall (Catch Rate)':<24} | {self.recall * 100:>14.2f}% |",
            f"| {'Precision':<24} | {self.precision * 100:>14.2f}% |",
            f"| {'False Positive Rate (FPR)':<24} | {self.fpr * 100:>14.2f}% |",
            f"| {'Accuracy':<24} | {self.accuracy * 100:>14.2f}% |",
            f"| {'Mean Hook Latency':<24} | {self.mean_latency_ms:>13.3f} ms |",
            f"| {'p95 Hook Latency':<24} | {self.p95_latency_ms:>13.3f} ms |",
            divider,
            f" True Positives  (TP) : {self.tp}",
            f" True Negatives  (TN) : {self.tn}",
            f" False Negatives (FN) : {self.fn} (missed attacks)",
            f" False Positives (FP) : {self.fp} (falsely blocked)",
            "===========================================================",
        ]
        if self.missed_attacks:
            lines.append("\n[!] Missed Attack Payloads:")
            for m in self.missed_attacks[:5]:
                lines.append(f"  - {m.get('input')} (Rule: {m.get('rule_id')})")
        if self.false_positives:
            lines.append("\n[!] False Positive Hits on Benign Work:")
            for fp in self.false_positives[:5]:
                lines.append(f"  - {fp.get('input')} (Blocked as: {fp.get('blocked_by')})")
        lines.append("")
        return "\n".join(lines)


class BenchmarkRunner:
    """Executes benchmark over the corpus and computes verified statistics."""

    def __init__(
        self,
        corpus_dir: Path | str | None = None,
        config: RedlineConfig | None = None,
    ) -> None:
        self.corpus_dir = Path(corpus_dir) if corpus_dir else Path("corpus")
        self.config = config or load_config()
        self.config.mode = Mode.BALANCED
        self.engine = Engine(config=self.config)

    def _item_to_tool_call(self, item: dict[str, Any]) -> ToolCall:
        tool_str = item.get("tool", "shell")
        inp = item["input"]
        if tool_str in ("read", "write", "fetch"):
            kind = ToolKind(tool_str)
            return ToolCall(kind=kind, paths=[inp])
        return ToolCall(kind=ToolKind.SHELL, command=inp)

    def run(self) -> BenchmarkResult:
        """Run full evaluation suite across malicious.jsonl and benign.jsonl."""
        mal_file = self.corpus_dir / "malicious.jsonl"
        ben_file = self.corpus_dir / "benign.jsonl"

        if not mal_file.is_file() or not ben_file.is_file():
            raise FileNotFoundError(
                f"Corpus files not found in {self.corpus_dir}. "
                "Ensure corpus/malicious.jsonl and corpus/benign.jsonl exist."
            )

        malicious_samples: list[dict[str, Any]] = []
        with mal_file.open("r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    malicious_samples.append(json.loads(stripped))

        benign_samples: list[dict[str, Any]] = []
        with ben_file.open("r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    benign_samples.append(json.loads(stripped))

        latencies_ms: list[float] = []
        tp = 0
        fn = 0
        tn = 0
        fp = 0
        missed: list[dict[str, Any]] = []
        false_positives: list[dict[str, Any]] = []

        # 1. Evaluate malicious samples
        for item in malicious_samples:
            tc = self._item_to_tool_call(item)

            t0 = time.perf_counter()
            verdict = self.engine.evaluate(tc)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            latencies_ms.append(elapsed_ms)

            if verdict.is_blocked:
                tp += 1
            else:
                fn += 1
                missed.append(item)

        # 2. Evaluate benign samples
        for item in benign_samples:
            tc = self._item_to_tool_call(item)

            t0 = time.perf_counter()
            verdict = self.engine.evaluate(tc)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            latencies_ms.append(elapsed_ms)

            if verdict.decision == Decision.ALLOW:
                tn += 1
            else:
                fp += 1
                item_copy = dict(item)
                item_copy["blocked_by"] = verdict.rule_id
                false_positives.append(item_copy)

        total = len(malicious_samples) + len(benign_samples)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        accuracy = (tp + tn) / total if total > 0 else 0.0

        mean_lat = statistics.mean(latencies_ms) if latencies_ms else 0.0
        p95_lat = statistics.quantiles(latencies_ms, n=20)[18] if len(latencies_ms) >= 20 else mean_lat

        return BenchmarkResult(
            total_evaluated=total,
            malicious_count=len(malicious_samples),
            benign_count=len(benign_samples),
            tp=tp,
            fn=fn,
            tn=tn,
            fp=fp,
            precision=precision,
            recall=recall,
            fpr=fpr,
            accuracy=accuracy,
            mean_latency_ms=mean_lat,
            p95_latency_ms=p95_lat,
            missed_attacks=missed,
            false_positives=false_positives,
        )
