"""guardrail — AI-powered commit auditor backed by TypeSafe System One (Jev)."""

import os
import subprocess
from pathlib import Path
from time import perf_counter
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from typesafe_sdk import (
    Choice,
    Noul,
    Score,
    TypeSafeAPIConnectionError,
    TypeSafeAPIError,
    TypeSafeBadRequestError,
    TypeSafeClient,
    TypeSafeError,
)

app = typer.Typer(
    name="guardrail",
    help="Audit code changes with TypeSafe System One (Jev) before they land.",
    add_completion=False,
)
console = Console()

BLOCK_THRESHOLD = 0.8
QUALITY_THRESHOLD = 3.0
MAX_STATE_CHARS = 200_000
CHUNK_CHARS = 50_000  # ~26k tokens, safely under the API's ~32k input limit
MAX_FILE_BYTES = 512 * 1024

SKIP_DIRS = frozenset(
    {
        ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
        ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".idea",
        ".vscode", "dist", "build", ".next", "target", "vendor",
    }
)

# One system_one call evaluates all four atomic questions in parallel.
QUESTIONS = {
    "has_secret_leak": Noul(
        instructions="Mã nguồn trong state có chứa API Key, Secret Token, "
        "Private Key hay Password hardcode không?",
        criteria={
            "true": "secret THẬT nhúng trong code/config: khoá PEM/OpenSSH, "
            "token, password, connection string có credential, file .env "
            "chứa giá trị thật",
            "false": "placeholder (YOUR_KEY_HERE, changeme, example, dummy, "
            "test-), đọc qua os.environ/getenv/vault, giá trị example kinh "
            "điển trong docs, hoặc không có secret",
        },
    ),
    "has_vulnerability": Noul(
        instructions="Mã nguồn có chứa lỗ hổng bảo mật nghiêm trọng không?",
        criteria={
            "true": "SQL/NoSQL/LDAP injection, command injection, XSS, SSTI, "
            "insecure deserialization (pickle.loads, yaml.load không safe), "
            "SSRF, path traversal, tắt verify chữ ký JWT/TLS, XXE",
            "false": "đã parameterize/sanitize/verify đúng cách, hoặc chỉ là "
            "hygiene issue nhẹ (debug mode, weak hash, missing timeout)",
        },
    ),
    # Score levels are 0-indexed by the API; labels document the 1-5 meaning
    # and the raw index is mapped +1 before display.
    "code_quality": Score(
        instructions="Chấm điểm chất lượng mã nguồn trên thang điểm từ 1 đến 5.",
        criteria=[
            "1 — code lỗi/không chạy được, bỏ qua mọi convention",
            "2 — logic mơ hồ, thiếu xử lý lỗi, khó bảo trì",
            "3 — chạy đúng nhưng còn nhiều chỗ cần cải thiện",
            "4 — rõ ràng, đúng convention, xử lý lỗi hợp lý",
            "5 — sạch, idiomatic, dễ test và bảo trì",
        ],
    ),
    "change_scope": Choice(
        instructions="Phạm vi của thay đổi này là gì?",
        criteria={
            "Minor_Fix": "sửa nhỏ: typo, comment, format — không đổi hành vi",
            "Refactor": "tái cấu trúc nội bộ — hành vi giữ nguyên",
            "Breaking_Change": "đổi API contract/schema/hành vi tương thích ngược",
            "Critical_Core": "chạm logic lõi: auth, payment, security, data layer",
        },
    ),
}

HOOK_BEGIN = "# >>> guardrail >>>"
HOOK_END = "# <<< guardrail <<<"
HOOK_BLOCK = f"""{HOOK_BEGIN}
if ! command -v guardrail >/dev/null 2>&1; then
    echo "guardrail: CLI not found on PATH - commit blocked." >&2
    echo "guardrail: reinstall it, or remove this block from .git/hooks/pre-commit." >&2
    exit 1
fi
guardrail audit
{HOOK_END}"""


class AuditError(Exception):
    pass


def _eval(client: TypeSafeClient, text: str, source: str) -> list:
    """Evaluate one state; recursively halve if it exceeds the API token limit."""
    try:
        return [
            client.system_one(
                state={"document": text, "source": source},
                questions=QUESTIONS,
            )
        ]
    except TypeSafeBadRequestError as e:
        if "max_tokens_exceeded" in str(e.body) and len(text) > 10_000:
            mid = len(text) // 2
            return _eval(client, text[:mid], source) + _eval(client, text[mid:], source)
        raise


def _abort(title: str, message: str) -> None:
    console.print(Panel(message, title=title, style="red"))
    raise typer.Exit(1)


def _git(*args: str) -> subprocess.CompletedProcess:
    # errors="replace": git diff can emit non-UTF-8 bytes for binary-ish or
    # non-UTF-8-encoded files (no NUL → git treats them as text).
    return subprocess.run(
        ["git", *args], capture_output=True, text=True, errors="replace"
    )


def _collect_git_diff() -> str:
    if _git("rev-parse", "--is-inside-work-tree").returncode != 0:
        raise AuditError(
            "Not inside a git repository. Pass a PATH to audit, or run inside a repo."
        )
    has_head = _git("rev-parse", "--verify", "HEAD").returncode == 0
    result = _git("diff", "HEAD") if has_head else _git("diff", "--cached")
    if result.returncode != 0:
        raise AuditError(f"git diff failed: {result.stderr.strip()}")
    return result.stdout


def _collect_path(path: Path) -> str:
    if path.is_file():
        return path.read_text(encoding="utf-8", errors="replace")
    if not path.is_dir():
        raise AuditError(f"Path not found: {path}")

    chunks: list[str] = []
    total = 0
    truncated = False
    for file in sorted(path.rglob("*")):
        if not file.is_file() or SKIP_DIRS & set(file.parts):
            continue
        try:
            data = file.read_bytes()
        except OSError:
            continue
        if len(data) > MAX_FILE_BYTES or b"\0" in data[:8192]:
            continue
        chunk = f"=== {file.relative_to(path)} ===\n{data.decode('utf-8', errors='replace')}\n"
        if total + len(chunk) > MAX_STATE_CHARS:
            truncated = True
            break
        chunks.append(chunk)
        total += len(chunk)
    if truncated:
        chunks.append(f"\n[... truncated: exceeded {MAX_STATE_CHARS} chars ...]")
    return "".join(chunks)


@app.command()
def audit(
    path: Annotated[
        Optional[Path],
        typer.Argument(
            help="File or directory to audit. Omit to audit `git diff HEAD` "
            "(staged + unstaged vs last commit)."
        ),
    ] = None,
) -> None:
    """Audit a diff, file, or directory and block on security threats."""
    try:
        if path is None:
            state_text, source = _collect_git_diff(), "git diff HEAD (staged + unstaged)"
        else:
            state_text, source = _collect_path(path), str(path)
    except AuditError as e:
        _abort("GUARDRAIL ERROR", str(e))
    except OSError as e:
        _abort("GUARDRAIL ERROR", f"Cannot read input: {e}")

    if not state_text.strip():
        console.print("[dim]Nothing to audit — no changes found.[/dim]")
        raise typer.Exit(0)

    if not os.environ.get("TYPESAFE_API_KEY"):
        _abort(
            "GUARDRAIL ERROR",
            "TYPESAFE_API_KEY is not set.\n\n"
            "Export your key (https://console.typesafe.ai/) and retry, "
            "or bypass with `git commit --no-verify`.",
        )

    latency_ms = 0.0
    chunks = [
        state_text[i : i + CHUNK_CHARS]
        for i in range(0, len(state_text), CHUNK_CHARS)
    ]
    responses = []
    try:
        with TypeSafeClient() as client:
            for chunk in chunks:
                started = perf_counter()
                responses.extend(_eval(client, chunk, source))
                latency_ms += (perf_counter() - started) * 1000
    except TypeSafeAPIConnectionError as e:
        _abort(
            "GUARDRAIL ERROR",
            f"Cannot reach the TypeSafe API: {e}\n\n"
            "Check your network, or bypass with `git commit --no-verify`.",
        )
    except TypeSafeAPIError as e:
        _abort(
            "GUARDRAIL ERROR",
            f"TypeSafe API error (status={e.status}, request_id={e.request_id}): {e.body}",
        )
    except TypeSafeError as e:
        _abort("GUARDRAIL ERROR", f"TypeSafe SDK error: {e}")

    secret = max(r.nouls["has_secret_leak"].noul for r in responses)
    vuln = max(r.nouls["has_vulnerability"].noul for r in responses)
    quality_ans = min(
        responses, key=lambda r: r.scores["code_quality"].score
    ).scores["code_quality"]
    quality = quality_ans.score + 1.0
    scope_ans = max(
        responses, key=lambda r: r.choices["change_scope"].confidence
    ).choices["change_scope"]

    blocked = []
    if secret > BLOCK_THRESHOLD:
        blocked.append(f"secret leak detected (noul={secret:.2f})")
    if vuln > BLOCK_THRESHOLD:
        blocked.append(f"vulnerability detected (noul={vuln:.2f})")

    table = Table(title=f"guardrail audit — {source}", show_lines=False)
    table.add_column("Check", style="bold")
    table.add_column("Result / Score")
    table.add_column("Confidence", justify="right")
    table.add_column("Status", justify="center")
    table.add_row(
        "has_secret_leak",
        f"{secret:.2f}",
        "—",
        "[red]BLOCK[/red]" if secret > BLOCK_THRESHOLD else "[green]OK[/green]",
    )
    table.add_row(
        "has_vulnerability",
        f"{vuln:.2f}",
        "—",
        "[red]BLOCK[/red]" if vuln > BLOCK_THRESHOLD else "[green]OK[/green]",
    )
    table.add_row(
        "code_quality",
        f"{quality:.1f} / 5",
        f"{quality_ans.confidence:.2f}",
        "[yellow]WARN[/yellow]" if quality < QUALITY_THRESHOLD else "[green]OK[/green]",
    )
    table.add_row(
        "change_scope",
        scope_ans.choice,
        f"{scope_ans.confidence:.2f}",
        "[cyan]INFO[/cyan]",
    )

    chunk_info = f" · {len(responses)} chunks" if len(responses) > 1 else ""
    console.print(
        Panel(
            f"[bold]🛡  GUARDRAIL[/bold] — AI Commit Audit\n"
            f"⚡ Evaluated in {latency_ms:.0f}ms{chunk_info} "
            f"(model: {responses[0].model})",
            style="blue",
        )
    )
    console.print(table)

    if blocked:
        _abort(
            "❌ COMMIT BLOCKED: Critical Security Threat Detected!",
            "\n".join(f"• {reason}" for reason in blocked)
            + "\n\nFix the issues above, or bypass with `git commit --no-verify`.",
        )
    if quality < QUALITY_THRESHOLD:
        console.print(
            Panel(
                f"⚠️  WARNING: Low code quality score ({quality:.1f} / 5)",
                style="yellow",
            )
        )
    console.print(Panel("✅ PASSED: Code is clean and safe!", style="green"))
    raise typer.Exit(0)


@app.command("install-hook")
def install_hook() -> None:
    """Install guardrail as a .git/hooks/pre-commit hook in the current repo."""
    result = _git("rev-parse", "--git-dir")
    if result.returncode != 0:
        _abort("GUARDRAIL ERROR", "Not inside a git repository.")

    git_dir = Path(result.stdout.strip())
    if not git_dir.is_absolute():
        git_dir = (Path.cwd() / git_dir).resolve()
    hook = git_dir / "hooks" / "pre-commit"
    hook.parent.mkdir(parents=True, exist_ok=True)

    if hook.exists():
        content = hook.read_text(encoding="utf-8")
        if HOOK_BEGIN in content and HOOK_END in content:
            before, _, rest = content.partition(HOOK_BEGIN)
            _, _, after = rest.partition(HOOK_END)
            new_content = before + HOOK_BLOCK + after
        else:
            new_content = content.rstrip("\n") + "\n\n" + HOOK_BLOCK + "\n"
    else:
        new_content = "#!/bin/sh\n\n" + HOOK_BLOCK + "\n"

    hook.write_text(new_content, encoding="utf-8")
    hook.chmod(hook.stat().st_mode | 0o111)
    console.print(f"[green]Installed pre-commit hook → {hook}[/green]")


if __name__ == "__main__":
    app()
