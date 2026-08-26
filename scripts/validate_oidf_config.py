#!/usr/bin/env python3
"""Validate a secret OIDF Basic OP configuration without reproducing secrets."""

import argparse
import copy
import json
import os
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any

REQUIRED_ERROR_OVERRIDES = {
    "oidcc-ensure-registered-redirect-uri",
    "oidcc-ensure-request-object-with-redirect-uri",
}
LEGACY_ERROR_OVERRIDES = {"oidcc-response-type-missing"}
ALLOWED_INPUT_ERROR_OVERRIDES = REQUIRED_ERROR_OVERRIDES | LEGACY_ERROR_OVERRIDES
EXPECTED_ERROR_PATTERNS = {
    "oidcc-response-type-missing": "invalid_request",
    "oidcc-ensure-registered-redirect-uri": "invalid_request",
    "oidcc-ensure-request-object-with-redirect-uri": "request_not_supported",
}
HOSTED_SUITE = "https://www.certification.openid.net"
HOSTED_CALLBACK_MATCH = f"{HOSTED_SUITE}/test/*/callback*"


def load_object(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise TypeError("OIDF configuration must be a JSON object")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def well_known(issuer: str) -> str:
    parsed = urllib.parse.urlsplit(issuer)
    path = parsed.path.rstrip("/")
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            f"/.well-known/openid-configuration{path}",
            "",
            "",
        )
    )


def validate_issuer(value: str) -> str:
    issuer = value.rstrip("/")
    parsed = urllib.parse.urlsplit(issuer)
    require(parsed.scheme == "https", "--issuer must be HTTPS")
    require(
        parsed.hostname is not None
        and parsed.username is None
        and parsed.password is None,
        "--issuer must contain a valid host without userinfo",
    )
    require(
        not parsed.query and not parsed.fragment,
        "--issuer must not contain a query or fragment",
    )
    require(
        "\\" not in value
        and all(ord(char) >= 0x21 and ord(char) != 0x7F for char in value),
        "--issuer must not contain backslashes or control characters",
    )
    try:
        _ = parsed.port
    except ValueError as error:
        raise ValueError("--issuer contains an invalid port") from error
    return issuer


def validate_initial_access_token(value: Any, path: str) -> None:
    require(
        isinstance(value, str) and bool(value),
        f"{path} must be a non-empty string",
    )
    token_id, separator, secret = value.partition(".")
    require(
        bool(separator)
        and token_id.startswith("iat_")
        and len(token_id) <= 128
        and bool(secret)
        and len(secret) <= 256,
        f"{path} must use the iat_<id>.<secret> format",
    )


def validate_browser(browser: Any, path: str) -> tuple[int, int]:
    require(
        isinstance(browser, list) and bool(browser),
        f"{path} must contain unattended browser rules",
    )
    command_count = 0
    command_lengths = {
        "click": {3, 4},
        "text": {4, 5},
        "wait": {4, 5, 6},
        "wait-element-invisible": {4},
        "wait-element-visible": {4},
    }
    element_selectors = {"id", "name", "xpath", "css", "class"}
    wait_selectors = element_selectors | {"contains", "match"}
    placeholder_actions = {
        "update-image-placeholder",
        "update-image-placeholder-optional",
    }
    for index, rule in enumerate(browser):
        rule_path = f"{path}[{index}]"
        require(isinstance(rule, dict), f"{rule_path} must be an object")
        require(
            isinstance(rule.get("match"), str) and bool(rule["match"]),
            f"{rule_path}.match is required",
        )
        require(
            isinstance(rule.get("tasks"), list) and bool(rule["tasks"]),
            f"{rule_path}.tasks must not be empty",
        )
        for task_index, task in enumerate(rule["tasks"]):
            task_path = f"{rule_path}.tasks[{task_index}]"
            require(isinstance(task, dict), f"{task_path} must be an object")
            require(
                isinstance(task.get("task"), str) and bool(task["task"].strip()),
                f"{task_path}.task is required",
            )
            if "match" in task:
                require(
                    isinstance(task["match"], str) and bool(task["match"]),
                    f"{task_path}.match must be a non-empty string",
                )
            if "optional" in task:
                require(
                    isinstance(task["optional"], bool),
                    f"{task_path}.optional must be boolean",
                )
            commands = task.get("commands", [])
            require(
                isinstance(commands, list),
                f"{task_path}.commands must be an array",
            )
            for command_index, command in enumerate(commands):
                command_path = f"{task_path}.commands[{command_index}]"
                require(
                    isinstance(command, list) and bool(command),
                    f"{command_path} must be a non-empty array",
                )
                operation = command[0]
                require(
                    isinstance(operation, str) and operation.lower() in command_lengths,
                    f"{command_path} uses an unsupported operation",
                )
                operation = operation.lower()
                require(
                    len(command) in command_lengths[operation],
                    f"{command_path} has an invalid argument count",
                )
                selector = command[1]
                allowed_selectors = (
                    wait_selectors if operation == "wait" else element_selectors
                )
                require(
                    isinstance(selector, str) and selector.lower() in allowed_selectors,
                    f"{command_path} uses an unsupported selector",
                )
                require(
                    isinstance(command[2], str) and bool(command[2]),
                    f"{command_path} target must be a non-empty string",
                )
                if operation == "click" and len(command) == 4:
                    require(
                        command[3] == "optional",
                        f"{command_path} click flag must be optional",
                    )
                elif operation == "text":
                    require(
                        isinstance(command[3], str),
                        f"{command_path} text value must be a string",
                    )
                    if len(command) == 5:
                        require(
                            command[4] == "optional",
                            f"{command_path} text flag must be optional",
                        )
                elif operation in {
                    "wait",
                    "wait-element-invisible",
                    "wait-element-visible",
                }:
                    require(
                        isinstance(command[3], int)
                        and not isinstance(command[3], bool)
                        and command[3] > 0,
                        f"{command_path} timeout must be a positive integer",
                    )
                    if operation == "wait":
                        if selector.lower() in {"contains", "match"}:
                            require(
                                len(command) == 4,
                                f"{command_path} URL wait accepts no regex or action",
                            )
                        if len(command) >= 5:
                            require(
                                isinstance(command[4], str),
                                f"{command_path} wait regex must be a string",
                            )
                        if len(command) == 6:
                            require(
                                command[5] in placeholder_actions,
                                f"{command_path} uses an unsupported placeholder action",
                            )
                command_count += 1
    return len(browser), command_count


def validate_basic_op_automation(
    browser: list[dict[str, Any]],
    override: dict[str, Any],
    issuer: str,
    login_hint: Any,
) -> None:
    require(
        isinstance(login_hint, str) and bool(login_hint),
        "config.server.login_hint must be a non-empty string",
    )
    require(
        len(browser) == 2,
        "config.browser must contain only prompt=none and general authorize rules",
    )
    general_authorize_indexes = [
        index
        for index, rule in enumerate(browser)
        if rule["match"] == f"{issuer}/authorize*"
    ]
    require(
        len(general_authorize_indexes) == 1,
        "config.browser must contain exactly one general authorize rule",
    )
    general_authorize_index = general_authorize_indexes[0]
    general_authorize_browser = [browser[general_authorize_index]]
    require(
        set(general_authorize_browser[0]) == {"match", "tasks"},
        "config.browser general authorize rule has unsupported fields",
    )
    general_tasks = general_authorize_browser[0]["tasks"]
    require(
        len(general_tasks) == 3
        and set(general_tasks[0]) == {"task", "match", "optional", "commands"}
        and general_tasks[0].get("match") == f"{issuer}/login*"
        and general_tasks[0].get("optional") is True
        and set(general_tasks[1]) == {"task", "match", "optional", "commands"}
        and general_tasks[1].get("match") == f"{issuer}/consent*"
        and general_tasks[1].get("optional") is True
        and set(general_tasks[2]) == {"task", "match", "commands"}
        and general_tasks[2].get("match") == HOSTED_CALLBACK_MATCH,
        "config.browser general authorize tasks must be login, consent, callback",
    )
    login_commands = general_tasks[0].get("commands", [])
    require(
        len(login_commands) == 6
        and len(login_commands[3]) == 4
        and login_commands[3][:3] == ["text", "id", "agent-auth-login-password"]
        and isinstance(login_commands[3][3], str)
        and bool(login_commands[3][3]),
        "config.browser login task must contain the generated command sequence",
    )
    password = login_commands[3][3]
    require(
        login_commands
        == [
            ["wait", "id", "agent-auth-login-email", 30],
            [
                "wait",
                "id",
                "agent-auth-login-email",
                30,
                ".*",
                "update-image-placeholder-optional",
            ],
            ["text", "id", "agent-auth-login-email", login_hint],
            ["text", "id", "agent-auth-login-password", password],
            ["click", "id", "agent-auth-login-submit"],
            ["wait", "contains", f"{issuer}/consent", 30],
        ],
        "config.browser login task must contain the generated command sequence",
    )
    require(
        general_tasks[1].get("commands", [])
        == [
            ["wait", "id", "agent-auth-consent-ready", 30],
            ["click", "id", "agent-auth-consent-approve"],
            ["wait", "contains", HOSTED_SUITE, 30],
        ],
        "config.browser consent task must contain the generated command sequence",
    )
    callback_commands = general_tasks[2].get("commands", [])
    require(
        callback_commands == [["wait", "id", "submission_complete", 30]],
        "config.browser callback task may only wait for submission_complete",
    )

    prompt_none_match = f"{issuer}/authorize*prompt=none*"
    prompt_none_indexes = [
        index
        for index, rule in enumerate(browser)
        if rule["match"] == prompt_none_match
    ]
    require(
        len(prompt_none_indexes) == 1,
        f"config.browser must contain exactly one {prompt_none_match} rule",
    )
    prompt_none_index = prompt_none_indexes[0]
    require(
        set(browser[prompt_none_index]) == {"match", "tasks"},
        "config.browser prompt=none rule has unsupported fields",
    )
    prompt_none_tasks = browser[prompt_none_index]["tasks"]
    require(
        len(prompt_none_tasks) == 1
        and set(prompt_none_tasks[0]) == {"task", "match", "commands"}
        and prompt_none_tasks[0].get("match") == HOSTED_CALLBACK_MATCH,
        "config.browser prompt=none rule must contain only the hosted callback task",
    )
    prompt_none_commands = prompt_none_tasks[0].get("commands", [])
    require(
        prompt_none_commands == [["wait", "id", "submission_complete", 30]],
        "config.browser prompt=none rule may only wait for submission_complete",
    )
    require(
        prompt_none_index == 0 and general_authorize_index == 1,
        "config.browser prompt=none and general authorize rules must be first",
    )

    missing_overrides = REQUIRED_ERROR_OVERRIDES - override.keys()
    if (
        "oidcc-ensure-request-object-with-redirect-uri" in missing_overrides
        and "oidcc-response-type-missing" in override
    ):
        missing_overrides.remove("oidcc-ensure-request-object-with-redirect-uri")
    unexpected_overrides = override.keys() - ALLOWED_INPUT_ERROR_OVERRIDES
    require(
        not missing_overrides and not unexpected_overrides,
        "config.override must contain the required modules and no unsupported "
        "modules; missing: "
        + ", ".join(sorted(missing_overrides))
        + "; unsupported: "
        + ", ".join(sorted(unexpected_overrides)),
    )
    for module_name in sorted(override):
        require(
            set(override[module_name]) == {"browser"},
            f"config.override.{module_name} has unsupported fields",
        )
        module_browser = override[module_name].get("browser")
        require(
            isinstance(module_browser, list),
            f"config.override.{module_name}.browser is required",
        )
        require(
            len(module_browser) == 1
            and set(module_browser[0]) == {"match", "tasks"}
            and module_browser[0].get("match") == f"{issuer}/authorize*"
            and len(module_browser[0]["tasks"]) == 1
            and set(module_browser[0]["tasks"][0])
            == {
                "task",
                "match",
                "commands",
            }
            and module_browser[0]["tasks"][0].get("match") == f"{issuer}/authorize*",
            f"config.override.{module_name}.browser must match the selected issuer",
        )
        commands = module_browser[0]["tasks"][0].get("commands", [])
        require(
            commands
            == [
                [
                    "wait",
                    "xpath",
                    "//*",
                    30,
                    EXPECTED_ERROR_PATTERNS[module_name],
                    "update-image-placeholder",
                ]
            ],
            f"config.override.{module_name}.browser captures the wrong error",
        )


def atomic_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        text=True,
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            json.dump(value, handle, separators=(",", ":"))
            handle.write("\n")
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        Path(temporary).unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--normalized-config", type=Path)
    args = parser.parse_args()

    try:
        issuer = validate_issuer(args.issuer)
        config = load_object(args.config)
        server = config.get("server")
        require(isinstance(server, dict), "config.server must be an object")
        require(
            server.get("discoveryUrl") == well_known(issuer),
            "config.server.discoveryUrl does not match the selected issuer",
        )
        for client_name in ("client", "client2"):
            client = config.get(client_name)
            require(
                isinstance(client, dict),
                f"config.{client_name} must be an object for dynamic registration",
            )
            require(
                isinstance(client.get("client_name"), str)
                and bool(client["client_name"].strip()),
                f"config.{client_name}.client_name is required",
            )
            validate_initial_access_token(
                client.get("initial_access_token"),
                f"config.{client_name}.initial_access_token",
            )
        browser = config.get("browser")
        browser_rule_count, browser_command_count = validate_browser(
            browser,
            "config.browser",
        )
        require(
            browser_command_count > 0,
            "config.browser must contain at least one automation command",
        )
        override = config.get("override", {})
        require(isinstance(override, dict), "config.override must be an object")
        for module_name, module_override in override.items():
            require(
                isinstance(module_name, str) and bool(module_name.strip()),
                "config.override module names must be non-empty strings",
            )
            require(
                isinstance(module_override, dict),
                f"config.override.{module_name} must be an object",
            )
            if "browser" in module_override:
                validate_browser(
                    module_override["browser"],
                    f"config.override.{module_name}.browser",
                )
        validate_basic_op_automation(
            browser,
            override,
            issuer,
            server.get("login_hint"),
        )
        normalized_config = copy.deepcopy(config)
        normalized_override = normalized_config.get("override")
        assert isinstance(normalized_override, dict)
        legacy_override = normalized_override.pop(
            "oidcc-response-type-missing",
            None,
        )
        if "oidcc-ensure-request-object-with-redirect-uri" not in normalized_override:
            assert isinstance(legacy_override, dict)
            request_object_override = copy.deepcopy(legacy_override)
            request_object_override["browser"][0]["tasks"][0]["commands"][0][4] = (
                EXPECTED_ERROR_PATTERNS["oidcc-ensure-request-object-with-redirect-uri"]
            )
            normalized_override["oidcc-ensure-request-object-with-redirect-uri"] = (
                request_object_override
            )
        require(
            set(normalized_override) == REQUIRED_ERROR_OVERRIDES,
            "normalized config.override does not contain exactly the required modules",
        )

        override_rule_count = 0
        override_command_count = 0
        for module_name, module_override in normalized_override.items():
            rules, commands = validate_browser(
                module_override["browser"],
                f"config.override.{module_name}.browser",
            )
            override_rule_count += rules
            override_command_count += commands

        if args.normalized_config is not None:
            atomic_write(args.normalized_config, normalized_config)
        manifest = {
            "schema_version": 1,
            "issuer": issuer,
            "discovery_url": well_known(issuer),
            "client_slots": ["client", "client2"],
            "initial_access_token_slots": ["client", "client2"],
            "browser_rule_count": browser_rule_count,
            "browser_command_count": browser_command_count,
            "browser_override_count": len(normalized_override),
            "browser_override_rule_count": override_rule_count,
            "browser_override_command_count": override_command_count,
            "description_present": isinstance(config.get("description"), str)
            and bool(config["description"].strip()),
        }
        args.summary.write_text(
            json.dumps(manifest, indent=2) + "\n",
            encoding="utf-8",
        )
        return 0
    except (json.JSONDecodeError, OSError, TypeError, ValueError) as error:
        args.summary.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "valid": False,
                    "error": str(error),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
