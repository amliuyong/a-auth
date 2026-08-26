#!/usr/bin/env python3
"""Validate conformance requirement-to-automation and live-evidence mappings."""

import argparse
import ast
import json
import re
import stat
import sys
from pathlib import Path
from typing import Any

try:
    from scripts.conformance_inventory import (
        APPLICABILITY,
        Requirement,
        load_object,
        parse_requirements,
        require,
        requirement_ids_sha256,
        validate_inventory,
    )
except ModuleNotFoundError:
    from conformance_inventory import (  # type: ignore[no-redef]
        APPLICABILITY,
        Requirement,
        load_object,
        parse_requirements,
        require,
        requirement_ids_sha256,
        validate_inventory,
    )

TARGET_ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
RUST_TEST = re.compile(r"(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
RUST_TEST_ATTRIBUTE = re.compile(
    r"#\[(?:[A-Za-z_][A-Za-z0-9_]*::)*test(?:\([^]]*\))?\]"
)
RUST_PATH_MODULE = re.compile(
    r'#\[\s*path\s*=\s*"([^"]+)"\s*\]\s*'
    r"(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;"
)
RUN_EXACT_CALL = re.compile(
    r"^\s*run_exact\s+([A-Za-z0-9_-]+)\s+([A-Za-z_][A-Za-z0-9_]*)\s*$"
)
RUN_LIB_EXACT_CALL = re.compile(
    r"^\s*run_lib_exact\s+([A-Za-z0-9_-]+)\s+([A-Za-z_][A-Za-z0-9_:]*)\s*$"
)
RUN_PYTEST_EXACT_CALL = re.compile(
    r"^\s*run_pytest_exact\s+(\S+)\s+([A-Za-z_][A-Za-z0-9_]*)\s*$"
)
RUN_UNITTEST_EXACT_CALL = re.compile(
    r"^\s*run_unittest_exact\s+(\S+)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*$"
)
RUN_VITEST_EXACT_CALL = re.compile(
    r"^\s*run_vitest_exact\s+(\S+)\s+([A-Za-z_][A-Za-z0-9_]*)\s*$"
)
RUN_PLAYWRIGHT_EXACT_CALL = re.compile(
    r"^\s*run_playwright_exact\s+(\S+)\s+([A-Za-z_][A-Za-z0-9_]*)\s*$"
)
RUN_NODE_EXACT_CALL = re.compile(
    r"^\s*run_node_exact\s+(\S+)\s+([A-Za-z_][A-Za-z0-9_]*)\s*$"
)
PACKAGE_NAME = re.compile(r'^\s*name\s*=\s*"([^"]+)"\s*$')
RUST_CHAR_LITERAL = re.compile(
    r"""'(?:\\(?:[nrt0\\'"]|x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]{1,6}\})|[^\\'\n])'"""
)
RUST_RAW_STRING = re.compile(r'(?:b)?r(#{0,255})"')


def load_unique_object(path: Path) -> dict[str, Any]:
    """Load JSON while rejecting duplicate object keys at every nesting level."""

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, f"duplicate JSON key: {key}")
            result[key] = value
        return result

    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicates,
    )
    require(isinstance(value, dict), f"{path} must contain a JSON object")
    return value


def repository_path(root: Path, value: Any, field: str) -> Path:
    require(isinstance(value, str) and bool(value), f"{field} is required")
    path = Path(value)
    require(
        not path.is_absolute() and ".." not in path.parts,
        f"{field} must be repository-relative",
    )
    resolved = root / path
    require(resolved.is_file(), f"{field} does not exist: {value}")
    return resolved


def parse_workflow_steps(workflow: Path) -> dict[str, dict[str, str]]:
    """Parse stable job ids and step names from the repository's CI workflow."""

    jobs: dict[str, dict[str, str]] = {}
    current_job: str | None = None
    current_step: str | None = None
    current_block: list[str] = []
    in_jobs = False

    def finish_step() -> None:
        nonlocal current_step, current_block
        if current_job is not None and current_step is not None:
            jobs[current_job][current_step] = "\n".join(current_block)
        current_step = None
        current_block = []

    for line in workflow.read_text(encoding="utf-8").splitlines():
        if line == "jobs:":
            in_jobs = True
            continue
        if not in_jobs:
            continue
        job_match = re.fullmatch(r"  ([A-Za-z0-9_-]+):", line)
        if job_match:
            finish_step()
            current_job = job_match.group(1)
            jobs[current_job] = {}
            continue
        if current_job is None:
            continue
        step_match = re.fullmatch(r"      - name: (.+)", line)
        if step_match:
            finish_step()
            current_step = step_match.group(1).strip()
            current_block = [line]
            continue
        if current_step is not None:
            current_block.append(line)
    finish_step()
    require(bool(jobs), f"no jobs parsed from {workflow}")
    return jobs


def active_run_commands(step_block: str) -> list[str]:
    """Return active shell lines from a workflow step's run block."""

    commands: list[str] = []
    in_multiline_run = False
    run_indent = 0
    for line in step_block.splitlines():
        run_match = re.match(r"^(\s*)run:\s*(.*)$", line)
        if run_match:
            run_indent = len(run_match.group(1))
            value = run_match.group(2).strip()
            in_multiline_run = value in {"|", "|-", ">", ">-"}
            if value and not in_multiline_run and not value.startswith("#"):
                commands.append(value)
            continue
        if not in_multiline_run:
            continue
        stripped = line.strip()
        if stripped and len(line) - len(line.lstrip()) <= run_indent:
            in_multiline_run = False
            continue
        if stripped and not stripped.startswith("#"):
            commands.append(stripped)
    return commands


def strip_rust_non_code(source: str) -> str:
    """Remove comments and string contents while preserving code line boundaries."""

    output: list[str] = []
    index = 0
    block_depth = 0
    state = "code"
    raw_hashes = 0
    while index < len(source):
        char = source[index]
        pair = source[index : index + 2]
        if state == "line_comment":
            output.append("\n" if char == "\n" else " ")
            index += 1
            if char == "\n":
                state = "code"
            continue
        if state == "block_comment":
            if pair == "/*":
                block_depth += 1
                output.extend("  ")
                index += 2
                continue
            if pair == "*/":
                block_depth -= 1
                output.extend("  ")
                index += 2
                if block_depth == 0:
                    state = "code"
                continue
            output.append("\n" if char == "\n" else " ")
            index += 1
            continue
        if state == "string":
            output.append("\n" if char == "\n" else " ")
            index += 1
            if char == "\\" and index < len(source):
                output.append("\n" if source[index] == "\n" else " ")
                index += 1
            elif char == '"':
                state = "code"
            continue
        if state == "raw_string":
            terminator = '"' + ("#" * raw_hashes)
            if source.startswith(terminator, index):
                output.extend(" " * len(terminator))
                index += len(terminator)
                state = "code"
                continue
            output.append("\n" if char == "\n" else " ")
            index += 1
            continue

        if pair == "//":
            output.extend("  ")
            index += 2
            state = "line_comment"
            continue
        if pair == "/*":
            output.extend("  ")
            index += 2
            block_depth = 1
            state = "block_comment"
            continue
        char_literal = RUST_CHAR_LITERAL.match(source, index)
        if char_literal:
            token = char_literal.group(0)
            output.extend(" " * len(token))
            index += len(token)
            continue
        if char == '"':
            output.append(" ")
            index += 1
            state = "string"
            continue
        raw_match = RUST_RAW_STRING.match(source, index)
        if raw_match:
            token = raw_match.group(0)
            raw_hashes = len(raw_match.group(1))
            output.extend(" " * len(token))
            index += len(token)
            state = "raw_string"
            continue
        output.append(char)
        index += 1
    return "".join(output)


def rust_test_is_active(path: Path, selector: str) -> bool:
    lines = strip_rust_non_code(path.read_text(encoding="utf-8")).splitlines()
    for index, line in enumerate(lines):
        if line.lstrip().startswith("//"):
            continue
        match = RUST_TEST.search(line)
        if not match or match.group(1) != selector:
            continue
        attributes: list[str] = []
        for prior in reversed(lines[:index]):
            stripped = prior.strip()
            if not stripped or stripped.startswith(("//", "#[")):
                attributes.append(prior)
                continue
            break
        attribute_block = "\n".join(reversed(attributes))
        return (
            RUST_TEST_ATTRIBUTE.search(attribute_block) is not None
            and "#[ignore" not in attribute_block
        )
    return False


def python_node_is_skipped(
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
) -> bool:
    decorators = [ast.unparse(decorator) for decorator in node.decorator_list]
    return any(
        decorator.endswith((".skip", ".skipif"))
        or ".skip(" in decorator
        or ".skipif(" in decorator
        for decorator in decorators
    )


def python_test_is_active(path: Path, selector: str) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name == selector:
            return not python_node_is_skipped(node)
    return False


def python_unittest_test_is_active(
    path: Path,
    test_class: str,
    selector: str,
) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or node.name != test_class:
            continue
        if python_node_is_skipped(node):
            return False
        base_names = {ast.unparse(base) for base in node.bases}
        if not any(base.endswith("TestCase") for base in base_names):
            return False
        for member in node.body:
            if not isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if member.name == selector:
                return not python_node_is_skipped(member)
    return False


def typescript_test_is_active(path: Path, selector: str) -> bool:
    source_lines: list[str] = []
    in_block_comment = False
    for line in path.read_text(encoding="utf-8").splitlines():
        active: list[str] = []
        index = 0
        while index < len(line):
            if in_block_comment:
                end = line.find("*/", index)
                if end < 0:
                    index = len(line)
                    continue
                in_block_comment = False
                index = end + 2
                continue
            block = line.find("/*", index)
            comment = line.find("//", index)
            if comment >= 0 and (block < 0 or comment < block):
                active.append(line[index:comment])
                break
            if block >= 0:
                active.append(line[index:block])
                in_block_comment = True
                index = block + 2
                continue
            active.append(line[index:])
            break
        source_lines.append("".join(active))
    source = "\n".join(source_lines)
    pattern = re.compile(
        rf"(?<![A-Za-z0-9_.])(?:it|test)\s*\(\s*"
        rf"(?P<quote>['\"]){re.escape(selector)}(?P=quote)\s*,"
    )
    return pattern.search(source) is not None


def rust_source_module_parts(path: Path, manifest: Path) -> list[str]:
    source_root = manifest.parent / "src"
    try:
        relative = path.relative_to(source_root)
    except ValueError as error:
        raise ValueError(f"library source is outside {source_root}: {path}") from error
    parts = list(relative.with_suffix("").parts)
    if parts[-1] in {"lib", "main", "mod"}:
        parts.pop()
    return parts


def expected_library_selector(
    path: Path,
    manifest: Path,
    selector: str,
    module_owner: Path | None = None,
) -> str:
    parts = rust_source_module_parts(path, manifest)
    if module_owner is not None:
        owner_parts = rust_source_module_parts(module_owner, manifest)
        matches = []
        owner_source = module_owner.read_text(encoding="utf-8")
        owner_code = strip_rust_non_code(owner_source)
        for match in RUST_PATH_MODULE.finditer(owner_source):
            if owner_code[match.start()] != "#":
                continue
            declared_path, module_name = match.groups()
            if (module_owner.parent / declared_path).resolve() == path.resolve():
                matches.append(module_name)
        require(
            len(matches) == 1,
            "library module_owner must mount the source path exactly once",
        )
        return "::".join([*owner_parts, matches[0], selector])
    if parts and parts[-1].endswith("_tests"):
        return "::".join([*parts, selector])
    module = "::".join([*parts, "tests", selector])
    return module


def runner_invokes_selector(runner: Path, test_target: str, selector: str) -> bool:
    for line in runner.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("#"):
            continue
        match = RUN_EXACT_CALL.fullmatch(line)
        if match and match.groups() == (test_target, selector):
            return True
    return False


def runner_invokes_library_selector(
    runner: Path, package: str, cargo_selector: str
) -> bool:
    for line in runner.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("#"):
            continue
        match = RUN_LIB_EXACT_CALL.fullmatch(line)
        if match and match.groups() == (package, cargo_selector):
            return True
    return False


def runner_invokes_pytest_selector(runner: Path, test_path: str, selector: str) -> bool:
    for line in runner.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("#"):
            continue
        match = RUN_PYTEST_EXACT_CALL.fullmatch(line)
        if match and match.groups() == (test_path, selector):
            return True
    return False


def runner_invokes_unittest_selector(
    runner: Path,
    test_path: str,
    test_class: str,
    selector: str,
) -> bool:
    for line in runner.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("#"):
            continue
        match = RUN_UNITTEST_EXACT_CALL.fullmatch(line)
        if match and match.groups() == (test_path, test_class, selector):
            return True
    return False


def runner_invokes_vitest_selector(runner: Path, test_path: str, selector: str) -> bool:
    for line in runner.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("#"):
            continue
        match = RUN_VITEST_EXACT_CALL.fullmatch(line)
        if match and match.groups() == (test_path, selector):
            return True
    return False


def runner_invokes_playwright_selector(
    runner: Path, test_path: str, selector: str
) -> bool:
    for line in runner.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("#"):
            continue
        match = RUN_PLAYWRIGHT_EXACT_CALL.fullmatch(line)
        if match and match.groups() == (test_path, selector):
            return True
    return False


def runner_invokes_node_selector(runner: Path, test_path: str, selector: str) -> bool:
    for line in runner.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("#"):
            continue
        match = RUN_NODE_EXACT_CALL.fullmatch(line)
        if match and match.groups() == (test_path, selector):
            return True
    return False


def cargo_package(manifest: Path) -> str:
    for line in manifest.read_text(encoding="utf-8").splitlines():
        match = PACKAGE_NAME.fullmatch(line)
        if match:
            return match.group(1)
    raise ValueError(f"Cargo package name is missing: {manifest}")


def validate_targets(
    root: Path,
    workflow: Path,
    configured: Any,
) -> dict[str, dict[str, Any]]:
    require(
        isinstance(configured, dict) and bool(configured),
        "targets must be a non-empty object",
    )
    workflow_steps = parse_workflow_steps(workflow)
    targets: dict[str, dict[str, Any]] = {}
    for target_id, target in configured.items():
        require(
            isinstance(target_id, str) and TARGET_ID.fullmatch(target_id) is not None,
            f"invalid target id: {target_id}",
        )
        require(isinstance(target, dict), f"target {target_id} must be an object")
        kind = target.get("kind")
        require(
            kind in {"workflow_step", "repo_test", "recorded_live_reference"},
            f"target {target_id} has invalid kind",
        )
        coverage_level = target.get("coverage_level")
        require(
            coverage_level in {"suite", "exact", "recorded_reference"},
            f"target {target_id} has invalid coverage_level",
        )
        if kind == "workflow_step":
            require(
                coverage_level == "suite",
                f"workflow step {target_id} must be suite coverage",
            )
            job = target.get("job")
            step = target.get("step")
            require(
                isinstance(job, str) and job in workflow_steps,
                f"target {target_id} references missing CI job",
            )
            require(
                isinstance(step, str) and step in workflow_steps[job],
                f"target {target_id} references missing CI step",
            )
            run_commands = target.get("run_commands")
            require(
                isinstance(run_commands, list)
                and bool(run_commands)
                and all(
                    isinstance(command, str) and command for command in run_commands
                ),
                f"target {target_id} run_commands must be a non-empty string array",
            )
            block = workflow_steps[job][step]
            active_commands = active_run_commands(block)
            for command in run_commands:
                require(
                    command in active_commands,
                    f"target {target_id} CI step no longer runs required command",
                )
        elif kind == "repo_test":
            require(
                coverage_level == "exact",
                f"repo test {target_id} must be exact coverage",
            )
            path = repository_path(root, target.get("path"), f"target {target_id} path")
            selector = target.get("selector")
            require(
                isinstance(selector, str) and bool(selector),
                f"target {target_id} selector is required",
            )
            runner = repository_path(
                root, target.get("runner"), f"target {target_id} runner"
            )
            framework = target.get("framework", "rust")
            require(
                framework
                in {"rust", "pytest", "unittest", "vitest", "playwright", "node"},
                f"target {target_id} has invalid framework",
            )
            if framework == "rust":
                require(
                    rust_test_is_active(path, selector),
                    f"target {target_id} selector is missing or ignored",
                )
                cargo_target = target.get("cargo_target", "integration")
                require(
                    cargo_target in {"integration", "lib"},
                    f"target {target_id} has invalid cargo_target",
                )
                if cargo_target == "integration":
                    require(
                        runner_invokes_selector(runner, path.stem, selector),
                        f"target {target_id} selector is not executed by its runner",
                    )
                    require(
                        "package" not in target,
                        f"integration target {target_id} must not declare package",
                    )
                    require(
                        "module_owner" not in target,
                        f"integration target {target_id} must not declare module_owner",
                    )
                else:
                    package = target.get("package")
                    require(
                        isinstance(package, str) and bool(package),
                        f"library target {target_id} package is required",
                    )
                    manifest = repository_path(
                        root, target.get("manifest"), f"target {target_id} manifest"
                    )
                    require(
                        manifest.name == "Cargo.toml"
                        and manifest.parent in path.parents,
                        f"library target {target_id} manifest does not own source",
                    )
                    require(
                        cargo_package(manifest) == package,
                        f"library target {target_id} package does not own source",
                    )
                    cargo_selector = target.get("cargo_selector")
                    require(
                        isinstance(cargo_selector, str),
                        f"library target {target_id} cargo_selector is required",
                    )
                    module_owner_value = target.get("module_owner")
                    module_owner = (
                        repository_path(
                            root,
                            module_owner_value,
                            f"target {target_id} module_owner",
                        )
                        if module_owner_value is not None
                        else None
                    )
                    if module_owner is not None:
                        require(
                            manifest.parent in module_owner.parents,
                            f"library target {target_id} manifest does not own module_owner",
                        )
                    require(
                        cargo_selector
                        == expected_library_selector(
                            path,
                            manifest,
                            selector,
                            module_owner,
                        ),
                        f"library target {target_id} cargo_selector does not match source module",
                    )
                    require(
                        runner_invokes_library_selector(
                            runner, package, cargo_selector
                        ),
                        f"target {target_id} selector is not executed by its runner",
                    )
            elif framework == "pytest":
                require(
                    path.suffix == ".py" and python_test_is_active(path, selector),
                    f"target {target_id} selector is missing or ignored",
                )
                test_path = str(target.get("path"))
                require(
                    runner_invokes_pytest_selector(runner, test_path, selector),
                    f"target {target_id} selector is not executed by its runner",
                )
                require(
                    not any(
                        field in target
                        for field in (
                            "cargo_target",
                            "manifest",
                            "package",
                            "cargo_selector",
                            "module_owner",
                        )
                    ),
                    f"pytest target {target_id} must not declare Cargo fields",
                )
            elif framework == "unittest":
                test_class = target.get("test_class")
                require(
                    isinstance(test_class, str) and bool(test_class),
                    f"unittest target {target_id} test_class is required",
                )
                require(
                    path.suffix == ".py"
                    and python_unittest_test_is_active(path, test_class, selector),
                    f"target {target_id} selector is missing or ignored",
                )
                test_path = str(target.get("path"))
                require(
                    runner_invokes_unittest_selector(
                        runner,
                        test_path,
                        test_class,
                        selector,
                    ),
                    f"target {target_id} selector is not executed by its runner",
                )
                require(
                    not any(
                        field in target
                        for field in (
                            "cargo_target",
                            "manifest",
                            "package",
                            "cargo_selector",
                            "module_owner",
                        )
                    ),
                    f"unittest target {target_id} must not declare Cargo fields",
                )
            elif framework == "vitest":
                require(
                    path.suffix == ".ts" and typescript_test_is_active(path, selector),
                    f"target {target_id} selector is missing or ignored",
                )
                test_path = str(target.get("path"))
                require(
                    runner_invokes_vitest_selector(runner, test_path, selector),
                    f"target {target_id} selector is not executed by its runner",
                )
                require(
                    not any(
                        field in target
                        for field in (
                            "cargo_target",
                            "manifest",
                            "package",
                            "cargo_selector",
                            "module_owner",
                        )
                    ),
                    f"vitest target {target_id} must not declare Cargo fields",
                )
            elif framework == "playwright":
                require(
                    path.suffix == ".ts" and typescript_test_is_active(path, selector),
                    f"target {target_id} selector is missing or ignored",
                )
                test_path = str(target.get("path"))
                require(
                    runner_invokes_playwright_selector(runner, test_path, selector),
                    f"target {target_id} selector is not executed by its runner",
                )
                require(
                    not any(
                        field in target
                        for field in (
                            "cargo_target",
                            "manifest",
                            "package",
                            "cargo_selector",
                            "module_owner",
                        )
                    ),
                    f"playwright target {target_id} must not declare Cargo fields",
                )
            else:
                require(
                    path.suffix in {".js", ".mjs", ".cjs"}
                    and typescript_test_is_active(path, selector),
                    f"target {target_id} selector is missing or ignored",
                )
                test_path = str(target.get("path"))
                require(
                    runner_invokes_node_selector(runner, test_path, selector),
                    f"target {target_id} selector is not executed by its runner",
                )
                require(
                    not any(
                        field in target
                        for field in (
                            "cargo_target",
                            "manifest",
                            "package",
                            "cargo_selector",
                            "module_owner",
                        )
                    ),
                    f"node target {target_id} must not declare Cargo fields",
                )
            ci_target = target.get("ci_target")
            require(
                isinstance(ci_target, str), f"target {target_id} ci_target is required"
            )
        else:
            require(
                coverage_level == "recorded_reference",
                f"recorded live reference {target_id} must not claim exact coverage",
            )
            require(
                target.get("verification") == "recorded_reference_only",
                f"recorded live reference {target_id} must declare its verification limit",
            )
            script = repository_path(
                root, target.get("script"), f"target {target_id} script"
            )
            require(
                script.stat().st_mode & stat.S_IXUSR,
                f"target {target_id} script is not executable",
            )
            require(
                GIT_COMMIT.fullmatch(str(target.get("deployment_commit"))) is not None,
                f"target {target_id} deployment_commit must be a full lowercase SHA",
            )
            require(
                SHA256.fullmatch(str(target.get("evidence_sha256"))) is not None,
                f"target {target_id} evidence_sha256 is invalid",
            )
        targets[target_id] = target

    for target_id, target in targets.items():
        if target["kind"] != "repo_test":
            continue
        ci_target = target["ci_target"]
        require(
            ci_target in targets,
            f"target {target_id} references missing ci_target {ci_target}",
        )
        linked = targets[ci_target]
        require(
            linked["kind"] == "workflow_step",
            f"target {target_id} ci_target must be a workflow step",
        )
        block = workflow_steps[linked["job"]][linked["step"]]
        runner_command = str(target["runner"])
        require(
            any(
                command in {runner_command, f"./{runner_command}"}
                for command in active_run_commands(block)
            ),
            f"target {target_id} runner is not invoked by its CI step",
        )
    return targets


def validate_requirement_mappings(
    requirements: list[Requirement],
    configured: Any,
    targets: dict[str, dict[str, Any]],
    incomplete: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    require(isinstance(configured, dict), "requirements mapping must be an object")
    expected_ids = {requirement.requirement_id for requirement in requirements}
    require(
        set(configured) == expected_ids,
        "requirement mappings do not match the document: "
        f"missing={sorted(expected_ids - set(configured))}, "
        f"extra={sorted(set(configured) - expected_ids)}",
    )
    by_id = {requirement.requirement_id: requirement for requirement in requirements}
    for requirement_id, entry in configured.items():
        require(
            isinstance(entry, dict),
            f"requirement mapping {requirement_id} must be an object",
        )
        requirement = by_id[requirement_id]
        applicability = entry.get("applicability")
        require(
            applicability in APPLICABILITY,
            f"requirement {requirement_id} has invalid applicability",
        )
        applicability_basis = entry.get("applicability_basis")
        require(
            isinstance(applicability_basis, str) and bool(applicability_basis.strip()),
            f"requirement {requirement_id} applicability_basis is required",
        )
        if requirement_id in incomplete:
            require(
                applicability == incomplete[requirement_id]["applicability"],
                f"requirement {requirement_id} applicability drifted",
            )
        automated_targets = entry.get("automated_targets")
        recorded_references = entry.get("recorded_references")
        require(
            isinstance(automated_targets, list)
            and all(
                isinstance(target, str) and target in targets
                for target in automated_targets
            ),
            f"requirement {requirement_id} has invalid automated_targets",
        )
        require(
            isinstance(recorded_references, list)
            and all(
                isinstance(target, str) and target in targets
                for target in recorded_references
            ),
            f"requirement {requirement_id} has invalid recorded_references",
        )
        require(
            len(set(automated_targets)) == len(automated_targets)
            and len(set(recorded_references)) == len(recorded_references),
            f"requirement {requirement_id} has duplicate targets",
        )
        for target_id in automated_targets:
            require(
                targets[target_id]["kind"] == "repo_test",
                f"requirement {requirement_id} automation must be an exact repo test",
            )
            require(
                str(targets[target_id]["selector"]) in requirement.test,
                f"requirement {requirement_id} row does not name exact selector",
            )
        for target_id in recorded_references:
            require(
                targets[target_id]["kind"] == "recorded_live_reference",
                f"requirement {requirement_id} reference target is not a recorded reference",
            )
        if applicability == "not_applicable":
            require(
                not automated_targets and not recorded_references,
                f"not-applicable requirement {requirement_id} must not claim active targets",
            )
        if requirement.status == "complete":
            require(
                bool(automated_targets),
                f"complete requirement {requirement_id} must retain exact automated targets",
            )
        coverage_level = entry.get("coverage_level")
        require(
            coverage_level in {"none", "exact"},
            f"requirement {requirement_id} has invalid coverage_level",
        )
        expected_level = "exact" if automated_targets else "none"
        require(
            coverage_level == expected_level,
            f"requirement {requirement_id} coverage_level drifted",
        )
        for target_id in recorded_references:
            target = targets[target_id]
            require(
                Path(str(target["script"])).name in requirement.test,
                f"requirement {requirement_id} row does not name evidence script",
            )
            require(
                str(target["deployment_commit"]) in requirement.test,
                f"requirement {requirement_id} row does not bind evidence commit",
            )
            require(
                str(target["evidence_sha256"]) in requirement.test,
                f"requirement {requirement_id} row does not bind evidence hash",
            )
    return configured


def validate_evidence_map(
    root: Path,
    document: Path,
    inventory_path: Path,
    evidence_map_path: Path,
    workflow: Path,
) -> tuple[dict[str, int], list[str]]:
    inventory = load_object(inventory_path)
    evidence_map = load_unique_object(evidence_map_path)
    require(
        evidence_map.get("schema_version") == 2, "evidence map schema_version must be 2"
    )
    require(
        evidence_map.get("document") == "docs/CONFORMANCE.md",
        "evidence map document must be docs/CONFORMANCE.md",
    )
    requirements, _ = parse_requirements(document)
    validate_inventory(document, inventory_path)
    require(
        evidence_map.get("requirement_ids_sha256")
        == requirement_ids_sha256(requirements),
        "evidence map requirement id digest drifted",
    )
    incomplete_entries = inventory.get("incomplete_requirements")
    require(
        isinstance(incomplete_entries, list),
        "inventory incomplete_requirements must be an array",
    )
    incomplete = {entry["id"]: entry for entry in incomplete_entries}
    targets = validate_targets(root, workflow, evidence_map.get("targets"))
    mappings = validate_requirement_mappings(
        requirements,
        evidence_map.get("requirements"),
        targets,
        incomplete,
    )
    exact_ids = [
        requirement.requirement_id
        for requirement in requirements
        if mappings[requirement.requirement_id]["coverage_level"] == "exact"
    ]
    complete = [
        requirement for requirement in requirements if requirement.status == "complete"
    ]
    unconditional_must = [
        requirement
        for requirement in complete
        if requirement.level.startswith("MUST")
        and mappings[requirement.requirement_id]["applicability"] == "unconditional"
    ]
    exact_unconditional_must = [
        requirement
        for requirement in unconditional_must
        if mappings[requirement.requirement_id]["coverage_level"] == "exact"
    ]
    applicability_counts = {
        applicability: sum(
            mapping["applicability"] == applicability for mapping in mappings.values()
        )
        for applicability in sorted(APPLICABILITY)
    }
    counts = {
        "total": len(requirements),
        "complete": len(complete),
        "unconditional_must": len(unconditional_must),
        "exact_unconditional_must": len(exact_unconditional_must),
        "exact": len(exact_ids),
        "complete_without_exact": sum(
            requirement.status == "complete"
            and mappings[requirement.requirement_id]["coverage_level"] != "exact"
            for requirement in requirements
        ),
        "applicability_unconditional": applicability_counts["unconditional"],
        "applicability_profile": applicability_counts["required_for_claimed_profile"],
        "applicability_not_applicable": applicability_counts["not_applicable"],
        "recorded_live_references": sum(
            len(mapping["recorded_references"]) for mapping in mappings.values()
        ),
    }
    return counts, exact_ids


def render_summary(counts: dict[str, int], exact_ids: list[str]) -> str:
    lines = [
        "# Conformance evidence map: PASS",
        "",
        f"- Total requirements mapped: {counts['total']}",
        f"- Complete requirements: {counts['complete']}",
        (
            "- Enabled unconditional MUST rows with exact selectors: "
            f"{counts['exact_unconditional_must']}/{counts['unconditional_must']}"
        ),
        (
            "- Explicit applicability: "
            f"{counts['applicability_unconditional']} unconditional, "
            f"{counts['applicability_profile']} profile/deployment scoped, "
            f"{counts['applicability_not_applicable']} not applicable"
        ),
        f"- Exact-selector coverage: {counts['exact']}",
        f"- Complete rows without exact selectors: {counts['complete_without_exact']}",
        f"- Recorded live references: {counts['recorded_live_references']}",
        "",
        "## Exact coverage IDs",
        "",
    ]
    lines.extend(f"- {requirement_id}" for requirement_id in exact_ids)
    lines.extend(
        [
            "",
            (
                "> Recorded live references bind reviewed metadata only; they are not "
                "retained artifacts and do not raise selector coverage."
            ),
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--document", required=True, type=Path)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--map", required=True, type=Path)
    parser.add_argument("--workflow", required=True, type=Path)
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args()
    try:
        root = args.root.resolve()
        counts, exact_ids = validate_evidence_map(
            root,
            args.document,
            args.inventory,
            args.map,
            args.workflow,
        )
        summary = render_summary(counts, exact_ids)
        if args.summary:
            with args.summary.open("a", encoding="utf-8") as output:
                output.write("\n" + summary)
        print(summary, end="")
        return 0
    except (json.JSONDecodeError, OSError, TypeError, ValueError) as error:
        print(f"Conformance evidence-map validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
