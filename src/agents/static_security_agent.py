"""Deterministic static + security analysis (no LLM, no network).

Two complementary scanners run over every candidate file:

* an **AST pass** using the stdlib ``ast`` module, which understands scope,
  decorators, argument lists and string composition; and
* a **regex pass** over raw source lines, which still catches things that
  parse fine but are textually dangerous (embedded bearer tokens, secrets in
  string literals that the AST sees as anonymous constants).

The agent is intentionally deterministic: identical input always yields an
identical finding list, which is what makes the CI quality gate trustworthy
and the benchmark reproducible.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from src.state import StaticIssue

# Severities allowed to block a PASS verdict (the gate policy).
BLOCKING_SEVERITIES = frozenset({"high", "critical"})

# ``code`` -> (severity, category, short title)
RULES: dict[str, tuple[str, str, str]] = {
    "HARDCODED_SECRET": ("critical", "security", "Hardcoded credential"),
    "EVAL_EXEC": ("critical", "security", "Dynamic code execution"),
    "SHELL_INJECTION": ("high", "security", "Shell execution with untrusted input"),
    "UNSAFE_DESERIALIZE": ("high", "security", "Unsafe deserialisation"),
    "SQL_STRING_FORMAT": ("high", "security", "SQL built by string formatting"),
    "BARE_EXCEPT": ("high", "correctness", "Bare except clause"),
    "BROAD_EXCEPT_PASS": ("medium", "correctness", "Silently swallowed exception"),
    "SYNTAX_ERROR": ("critical", "correctness", "File does not parse"),
    "MISSING_TYPE_HINT": ("low", "typing", "Missing type annotations"),
    "MISSING_DOCSTRING": ("low", "style", "Missing docstring"),
    "MUTABLE_DEFAULT_ARG": ("medium", "correctness", "Mutable default argument"),
    "WILDCARD_IMPORT": ("low", "style", "Wildcard import"),
}

_SECRET_NAME_RE = re.compile(
    r"(api[_-]?key|apikey|secret|token|passwd|password|passphrase|"
    r"private[_-]?key|access[_-]?key|auth[_-]?key|credential|client[_-]?secret)",
    re.IGNORECASE,
)

# Well-known credential shapes, applied to raw source text.
_SECRET_VALUE_RES = (
    re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{20,}=*"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)

_PLACEHOLDER_HINTS = (
    "your",
    "xxx",
    "changeme",
    "change-me",
    "placeholder",
    "example",
    "dummy",
    "sample",
    "redacted",
    "todo",
    "fixme",
    "<",
    ">",
    "{{",
    "}}",
    "${",
    "...",
    "none",
    "null",
    "empty",
    "test-key",
    "fake",
)

_SQL_RE = re.compile(
    r"\b(select\s+.+?\s+from|insert\s+into|update\s+\w+\s+set|delete\s+from|"
    r"replace\s+into|create\s+table|drop\s+table)\b",
    re.IGNORECASE | re.DOTALL,
)

_UNSAFE_CALLS = {"eval", "exec", "compile", "__import__"}
_SHELL_CALLS = {"system", "popen", "call", "run", "check_call", "check_output", "Popen"}


@dataclass
class _Finding:
    """Internal mutable finding, converted to a StaticIssue dict at the end."""

    code: str
    line: int
    message: str
    snippet: str = ""

    def to_issue(self) -> StaticIssue:
        severity, category, _title = RULES[self.code]
        return StaticIssue(
            code=self.code,
            severity=severity,  # type: ignore[typeddict-item]
            category=category,  # type: ignore[typeddict-item]
            line=max(1, self.line),
            message=self.message,
            snippet=self.snippet[:160],
        )


def _looks_like_secret_value(value: str) -> bool:
    """Heuristic: is this string literal plausibly a real credential?"""
    if not isinstance(value, str):
        return False
    s = value.strip()
    if len(s) < 8:
        return False
    low = s.lower()
    if any(hint in low for hint in _PLACEHOLDER_HINTS):
        return False
    if " " in s and not any(tok in low for tok in ("bearer", "key=", "token=")):
        # Real secrets do not contain spaces; prose does.
        return False
    has_digit = any(c.isdigit() for c in s)
    has_alpha = any(c.isalpha() for c in s)
    mixed_case = any(c.isupper() for c in s) and any(c.islower() for c in s)
    symbolish = any(not c.isalnum() for c in s)
    return (has_digit and has_alpha) or (mixed_case and (symbolish or len(s) >= 16))


def _target_name(node: ast.AST) -> str:
    """Best-effort name of an assignment target."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript):
        return _target_name(node.value)
    return ""


def _is_sql(text: str) -> bool:
    return bool(_SQL_RE.search(text or ""))


def _string_pieces(node: ast.AST) -> list[str]:
    """Flatten constant string parts of f-strings / concatenations."""
    out: list[str] = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            out.append(sub.value)
    return out


def _format_receiver(node: ast.Call) -> str:
    """Render ``cursor.execute(...)``-style receiver chains as text."""
    parts: list[str] = []
    cur: ast.AST | None = node.func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


class _Analyzer(ast.NodeVisitor):
    """AST visitor collecting findings."""

    def __init__(self, source: str) -> None:
        self.source = source
        self.lines = source.splitlines()
        self.findings: list[_Finding] = []

    # -- helpers -------------------------------------------------------
    def _snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()
        return ""

    def _add(self, code: str, lineno: int, message: str) -> None:
        self.findings.append(
            _Finding(code=code, line=lineno, message=message, snippet=self._snippet(lineno))
        )

    # -- assignments: secrets and SQL ---------------------------------
    def visit_Assign(self, node: ast.Assign) -> None:
        self._check_assignment(node.targets, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._check_assignment([node.target], node.value, node.lineno)
        self.generic_visit(node)

    def _check_assignment(self, targets: Iterable[ast.AST], value: ast.AST, lineno: int) -> None:
        names = [n for n in (_target_name(t) for t in targets) if n]
        if not names:
            return
        # Hardcoded secret: secret-ish name bound to a literal-looking value.
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            secret_named = any(_SECRET_NAME_RE.search(n) for n in names)
            if secret_named and _looks_like_secret_value(value.value):
                self._add(
                    "HARDCODED_SECRET",
                    lineno,
                    f"Credential-like value assigned to '{names[0]}'. "
                    "Read it from os.environ instead and fail fast when missing.",
                )
        # SQL assembled by f-string / % / .format / concatenation.
        sql_named = any(re.search(r"sql|query|stmt|statement", n, re.I) for n in names)
        built = self._is_built_string(value)
        if built:
            texts = "\n".join(_string_pieces(value))
            if _is_sql(texts) or (_is_sql(texts) and sql_named):
                self._add(
                    "SQL_STRING_FORMAT",
                    lineno,
                    "SQL statement assembled by string formatting/concatenation. "
                    "Use a static statement with '?' placeholders and a params tuple.",
                )

    def _is_built_string(self, node: ast.AST) -> bool:
        """True when ``node`` is an f-string, %-format, .format() or concat."""
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
            return True
        return bool(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"format", "format_map", "join"}
        )

    # -- calls ---------------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
        qual = _format_receiver(node)

        if isinstance(func, ast.Name) and name in _UNSAFE_CALLS:
            self._add(
                "EVAL_EXEC",
                node.lineno,
                f"Use of {name}() allows arbitrary code execution. "
                "Parse data with ast.literal_eval / json.loads instead.",
            )

        if name in _SHELL_CALLS and ("os" in qual or "subprocess" in qual or qual.endswith(name)):
            shell_true = any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            )
            dynamic = any(
                not (isinstance(a, ast.Constant) and isinstance(a.value, (str, list, tuple)))
                for a in node.args
            )
            if shell_true and dynamic:
                self._add(
                    "SHELL_INJECTION",
                    node.lineno,
                    "shell=True combined with a non-literal command. "
                    "Pass an argv list and keep shell=False.",
                )
            elif "os.system" in qual or qual.endswith("os.system"):
                self._add(
                    "SHELL_INJECTION",
                    node.lineno,
                    "os.system() executes through a shell. Use subprocess.run([...], shell=False).",
                )

        if name in {"load", "loads"} and ("pickle" in qual or "marshal" in qual):
            self._add(
                "UNSAFE_DESERIALIZE",
                node.lineno,
                "Deserialising untrusted bytes with pickle/marshal can execute code. "
                "Use json.loads for data interchange.",
            )

        if name == "execute" and node.args:
            arg = node.args[0]
            if self._is_built_string(arg) and _is_sql("\n".join(_string_pieces(arg))):
                self._add(
                    "SQL_STRING_FORMAT",
                    node.lineno,
                    "SQL passed to execute() is built by string formatting. "
                    "Use parameterised placeholders and a separate params tuple.",
                )
        self.generic_visit(node)

    # -- exception handling -------------------------------------------
    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is None:
            self._add(
                "BARE_EXCEPT",
                node.lineno,
                "Bare 'except:' swallows every error including KeyboardInterrupt "
                "and SystemExit. Catch the specific exception type.",
            )
        elif (
            isinstance(node.type, ast.Name)
            and node.type.id in {"Exception", "BaseException"}
            and len(node.body) == 1
            and isinstance(node.body[0], (ast.Pass, ast.Continue))
        ):
            self._add(
                "BROAD_EXCEPT_PASS",
                node.lineno,
                f"'{node.type.id}' handler only passes, hiding failures. "
                "Catch the expected type and re-raise or log.",
            )
        self.generic_visit(node)

    # -- functions -----------------------------------------------------
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)

    def _check_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        if node.name.startswith("_") and not node.name.startswith("__"):
            return  # private helper: advisory rules do not apply
        missing: list[str] = []
        args = list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
        for arg in args:
            if arg.arg in {"self", "cls"}:
                continue
            if arg.annotation is None:
                missing.append(arg.arg)
        if node.args.vararg and node.args.vararg.annotation is None:
            missing.append(f"*{node.args.vararg.arg}")
        if node.args.kwarg and node.args.kwarg.annotation is None:
            missing.append(f"**{node.args.kwarg.arg}")
        if node.returns is None:
            missing.append("return")
        if missing:
            self._add(
                "MISSING_TYPE_HINT",
                node.lineno,
                f"Function '{node.name}' is missing annotations for: {', '.join(missing)}.",
            )
        if not (ast.get_docstring(node) or "").strip():
            self._add(
                "MISSING_DOCSTRING",
                node.lineno,
                f"Public function '{node.name}' has no docstring.",
            )
        # Mutable default arguments (list/dict/set literals, or calls).
        for default in list(node.args.defaults) + [d for d in node.args.kw_defaults if d]:
            if isinstance(default, (ast.List, ast.Dict, ast.Set, ast.Call)):
                self._add(
                    "MUTABLE_DEFAULT_ARG",
                    node.lineno,
                    f"Function '{node.name}' uses a mutable default argument. "
                    "Default to None and build the value inside the body.",
                )
                break

    # -- imports -------------------------------------------------------
    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if any(alias.name == "*" for alias in node.names):
            self._add(
                "WILDCARD_IMPORT",
                node.lineno,
                f"Wildcard import from '{node.module}' hides the module's public surface.",
            )
        self.generic_visit(node)


def _regex_secret_findings(source: str, lines: list[str]) -> list[_Finding]:
    """Catch credential shapes anywhere in the text, including plain literals."""
    found: list[_Finding] = []
    seen_lines: set[int] = set()
    for pattern in _SECRET_VALUE_RES:
        for match in pattern.finditer(source):
            lineno = source.count("\n", 0, match.start()) + 1
            if lineno in seen_lines:
                continue
            seen_lines.add(lineno)
            snippet = lines[lineno - 1].strip() if 1 <= lineno <= len(lines) else ""
            found.append(
                _Finding(
                    code="HARDCODED_SECRET",
                    line=lineno,
                    message="Source contains a value matching a known credential "
                    f"pattern ({match.group(0)[:6]}…). Load it from the environment.",
                    snippet=snippet,
                )
            )
    return found


def scan_source(source: str) -> list[StaticIssue]:
    """Analyse one Python source string and return deduplicated findings.

    Findings are ordered by line, then rule code, so output is stable.
    """
    lines = (source or "").splitlines()
    findings: list[_Finding] = []
    try:
        tree = ast.parse(source or "")
    except SyntaxError as exc:
        return [
            StaticIssue(
                code="SYNTAX_ERROR",
                severity=RULES["SYNTAX_ERROR"][0],  # type: ignore[typeddict-item]
                category=RULES["SYNTAX_ERROR"][1],  # type: ignore[typeddict-item]
                line=int(exc.lineno or 1),
                message=f"SyntaxError: {exc.msg}. The module must import cleanly.",
                snippet=(lines[int(exc.lineno or 1) - 1].strip() if lines else ""),
            )
        ]

    analyzer = _Analyzer(source)
    analyzer.visit(tree)
    findings.extend(analyzer.findings)
    findings.extend(_regex_secret_findings(source, lines))

    deduped: dict[tuple[str, int], _Finding] = {}
    for finding in findings:
        deduped.setdefault((finding.code, finding.line), finding)
    ordered = sorted(deduped.values(), key=lambda f: (f.line, f.code))
    return [f.to_issue() for f in ordered]


def split_issues(issues: list[StaticIssue]) -> tuple[list[StaticIssue], list[StaticIssue]]:
    """Split findings into (static_issues, security_issues)."""
    static = [i for i in issues if i.get("category") != "security"]
    security = [i for i in issues if i.get("category") == "security"]
    return static, security


def blocking_issues(issues: list[StaticIssue]) -> list[StaticIssue]:
    """Return only the findings severe enough to fail the quality gate."""
    return [i for i in issues if i.get("severity") in BLOCKING_SEVERITIES]


def format_issues(issues: list[StaticIssue]) -> str:
    """Render findings as a compact, LLM-friendly bullet list."""
    if not issues:
        return "No issues found."
    out = []
    for issue in issues:
        out.append(
            f"- [{issue.get('severity', '?').upper()}] {issue.get('code')} "
            f"(line {issue.get('line', '?')}): {issue.get('message')}"
        )
    return "\n".join(out)


def make_static_security_node():
    """LangGraph node: scan ``generated_code`` and record findings."""

    def static_security_node(state: dict[str, Any]) -> dict[str, Any]:
        code = state.get("generated_code") or ""
        issues = scan_source(code)
        static, security = split_issues(issues)
        iteration = int(state.get("iterations") or 0)
        return {
            "static_issues": static,
            "security_issues": security,
            "history": [
                {
                    "node": "static_security",
                    "iteration": iteration,
                    "static_count": len(static),
                    "security_count": len(security),
                    "blocking": len(blocking_issues(issues)),
                }
            ],
        }

    return static_security_node


def agent_report(source: str) -> dict[str, Any]:
    """Convenience helper: full structured analysis of one file."""
    issues = scan_source(source)
    static, security = split_issues(issues)
    return {
        "issues": [dict(i) for i in issues],
        "static_issues": static,
        "security_issues": security,
        "blocking": blocking_issues(issues),
        "passed": not blocking_issues(issues),
    }
