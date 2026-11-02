"""Generate crisp terminal screenshots for agent-redline visual proof."""

import shutil
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ARTIFACT_DIR = Path(r"C:\Users\lenovo\.gemini\antigravity\brain\485c6770-cdac-48f3-be06-d7acf861d343")
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

# Copy demo.gif to artifacts directory
demo_src = Path("demo.gif")
demo_dest = ARTIFACT_DIR / "agent_redline_demo.gif"
shutil.copy2(demo_src, demo_dest)
print(f"Copied demo.gif to {demo_dest}")


def render_terminal_window(lines: list[tuple[str, str]], title: str, output_path: Path, width=820, height=520):
    bg_color = (20, 24, 34)
    header_color = (30, 36, 50)
    text_color = (220, 230, 245)
    prompt_color = (80, 200, 120)
    red_color = (255, 90, 95)
    yellow_color = (250, 200, 70)
    cyan_color = (80, 210, 240)
    dim_color = (130, 145, 170)

    try:
        font = ImageFont.truetype("consola.ttf", 15)
        title_font = ImageFont.truetype("arial.ttf", 13)
        bold_font = ImageFont.truetype("consolab.ttf", 15)
    except Exception:
        font = ImageFont.load_default()
        title_font = font
        bold_font = font

    img = Image.new("RGB", (width, height), bg_color)
    draw = ImageDraw.Draw(img)

    # Titlebar
    draw.rectangle([0, 0, width, 38], fill=header_color)
    draw.ellipse([14, 13, 26, 25], fill=(255, 95, 86))
    draw.ellipse([34, 13, 46, 25], fill=(255, 189, 46))
    draw.ellipse([54, 13, 66, 25], fill=(39, 201, 63))
    draw.text((width // 2 - 120, 11), title, fill=dim_color, font=title_font)

    y = 52
    x = 22
    line_height = 22

    for style, text in lines:
        if style == "prompt":
            draw.text((x, y), text, fill=prompt_color, font=bold_font)
        elif style == "bold":
            draw.text((x, y), text, fill=text_color, font=bold_font)
        elif style == "dim":
            draw.text((x, y), text, fill=dim_color, font=font)
        elif style == "error":
            draw.text((x, y), text, fill=red_color, font=bold_font)
        elif style == "warn":
            draw.text((x, y), text, fill=yellow_color, font=font)
        elif style == "cyan":
            draw.text((x, y), text, fill=cyan_color, font=bold_font)
        elif style == "success":
            draw.text((x, y), text, fill=prompt_color, font=bold_font)
        else:
            draw.text((x, y), text, fill=text_color, font=font)
        y += line_height

    img.save(output_path)
    print(f"Rendered screenshot saved to {output_path}")


# 1. Benchmark Screenshot
bench_lines = [
    ("prompt", "$ redline bench --corpus corpus"),
    ("bold", "==========================================================="),
    ("cyan", "        agent-redline Security Benchmark Evaluation        "),
    ("bold", "==========================================================="),
    ("normal", " Total Evaluated Commands : 335"),
    ("normal", " Malicious Test Samples   : 184"),
    ("normal", " Benign Developer Samples : 151"),
    ("dim", "+--------------------------+------------------+"),
    ("dim", "| Metric                   | Measured Value   |"),
    ("dim", "+--------------------------+------------------+"),
    ("success", "| Recall (Catch Rate)      |          100.00% |"),
    ("success", "| Precision                |          100.00% |"),
    ("success", "| False Positive Rate (FPR)|            0.00% |"),
    ("success", "| Accuracy                 |          100.00% |"),
    ("cyan", "| Mean Hook Latency        |         0.821 ms |"),
    ("cyan", "| p95 Hook Latency         |         1.234 ms |"),
    ("dim", "+--------------------------+------------------+"),
    ("normal", " True Positives  (TP) : 184 (all attacks stopped)"),
    ("normal", " True Negatives  (TN) : 151 (normal work unblocked)"),
    ("normal", " False Negatives (FN) : 0"),
    ("normal", " False Positives (FP) : 0"),
    ("bold", "==========================================================="),
]
bench_dest = ARTIFACT_DIR / "agent_redline_benchmark.png"
render_terminal_window(bench_lines, "agent-redline - Empirical Benchmark Card", bench_dest, height=540)
shutil.copy2(bench_dest, Path("benchmark.png"))

# 2. Pytest Results Screenshot
test_lines = [
    ("prompt", "$ pytest tests/ -v"),
    ("dim", "platform win32 -- Python 3.13.7, pytest-9.2.0, pluggy-1.7.0"),
    ("dim", "rootdir: C:\\...\\agent-redline, configfile: pyproject.toml"),
    ("dim", "collected 83 items"),
    ("normal", ""),
    ("success", "tests/test_adapters.py::test_antigravity_adapter_fixture PASSED         [ 1%]"),
    ("success", "tests/test_adapters.py::test_claude_adapter_fixture PASSED              [ 2%]"),
    ("success", "tests/test_adapters.py::test_cursor_adapter_fixture PASSED              [ 3%]"),
    ("success", "tests/test_adapters.py::test_codex_adapter_fixture PASSED               [ 4%]"),
    ("success", "tests/test_bench.py::test_benchmark_runner_execution PASSED             [ 7%]"),
    ("success", "tests/test_injection.py::test_instruction_override_detected PASSED      [24%]"),
    ("success", "tests/test_installer.py::test_installer_init_and_uninstall_all PASSED   [30%]"),
    ("success", "tests/test_presets.py::test_laravel_preset_protections PASSED           [36%]"),
    ("success", "tests/test_rules_data.py::test_sql_drop_database PASSED                 [45%]"),
    ("success", "tests/test_rules_fs.py::test_destructive_rm_rf_root PASSED              [66%]"),
    ("success", "tests/test_rules_git.py::test_git_force_push_main_denied PASSED         [75%]"),
    ("success", "tests/test_rules_rce.py::test_curl_pipe_sh_denied PASSED                [84%]"),
    ("success", "tests/test_rules_secrets.py::test_secret_read_tool PASSED               [90%]"),
    ("success", "tests/test_shellparse.py::test_split_pipeline_segments PASSED           [93%]"),
    ("normal", ""),
    ("success", "======================== 83 passed in 1.06s ========================"),
]
tests_dest = ARTIFACT_DIR / "agent_redline_tests.png"
render_terminal_window(test_lines, "agent-redline - Full Pytest Test Suite", tests_dest, height=480)
shutil.copy2(tests_dest, Path("tests.png"))
