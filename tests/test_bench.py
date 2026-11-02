"""Unit and integration tests for the benchmark engine."""

from pathlib import Path

from agent_redline.bench import BenchmarkResult, BenchmarkRunner
from agent_redline.cli import main


def test_benchmark_runner_execution():
    runner = BenchmarkRunner(corpus_dir=Path("corpus"))
    result = runner.run()

    assert isinstance(result, BenchmarkResult)
    assert result.total_evaluated >= 300
    assert result.malicious_count >= 150
    assert result.benign_count >= 150

    # Strict empirical quality gates
    assert result.recall >= 0.98, f"Recall too low: {result.recall}"
    assert result.fpr <= 0.02, f"False Positive Rate too high: {result.fpr}"
    assert result.precision >= 0.98, f"Precision too low: {result.precision}"
    assert result.mean_latency_ms < 10.0, f"Mean latency exceeds 10ms: {result.mean_latency_ms}ms"

    report = result.format_report()
    assert "agent-redline Security Benchmark Evaluation" in report
    assert "Recall (Catch Rate)" in report
    assert "Mean Hook Latency" in report


def test_cli_bench_subcommand(capsys):
    ret = main(["bench", "--corpus", "corpus"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "Security Benchmark Evaluation" in captured.out
    assert "Recall (Catch Rate)" in captured.out
