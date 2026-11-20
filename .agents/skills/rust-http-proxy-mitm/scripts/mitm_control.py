#!/usr/bin/env python3
"""Control rust_http_proxy MITM APIs portably using only the standard library."""

from __future__ import annotations

import argparse
import base64
import copy
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
}


class ApiClient:
    def __init__(
        self,
        base_url: str,
        username: str | None,
        password: str | None,
        insecure: bool,
        timeout: float,
    ) -> None:
        parsed = urllib.parse.urlsplit(base_url.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("--base-url must be an http(s) origin")
        path = parsed.path.rstrip("/")
        if path == "/mitm":
            path = ""
        if path:
            raise ValueError("--base-url must be an origin without a path")
        self.base_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", "")).rstrip("/")
        self.timeout = timeout
        self.headers = {"Accept": "application/json"}
        if username is not None:
            if password is None:
                raise ValueError("MITM_PASSWORD is required when a username is configured")
            token = base64.b64encode(f"{username}:{password}".encode()).decode()
            self.headers["Authorization"] = f"Basic {token}"
        self.context = ssl._create_unverified_context() if insecure else ssl.create_default_context()

    def request(
        self,
        method: str,
        path: str,
        payload: Any | None = None,
        query: dict[str, Any] | None = None,
    ) -> Any:
        url = f"{self.base_url}/mitm/api{path}"
        if query:
            values = {key: value for key, value in query.items() if value is not None}
            url = f"{url}?{urllib.parse.urlencode(values)}"
        body = None
        headers = dict(self.headers)
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                raw = response.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            raw = error.read().decode(errors="replace")
            try:
                message = json.loads(raw).get("error", raw)
            except json.JSONDecodeError:
                message = raw or error.reason
            hint = " Check MITM_USERNAME and MITM_PASSWORD." if error.code == 401 else ""
            raise RuntimeError(f"HTTP {error.code}: {message}.{hint}") from error
        except urllib.error.URLError as error:
            raise RuntimeError(f"request failed: {error.reason}") from error


def print_json(value: Any, compact: bool) -> None:
    if compact:
        print(json.dumps(value, ensure_ascii=False, separators=(",", ":")))
    else:
        print(json.dumps(value, ensure_ascii=False, indent=2))


def read_json(path: str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read JSON from {path}: {error}") from error


def find_target(client: ApiClient, target_id: int) -> dict[str, Any]:
    targets = client.request("GET", "/targets")
    target = next((item for item in targets if item["id"] == target_id), None)
    if target is None:
        raise ValueError(f"target {target_id} was not found")
    return target


def list_ui_stubs(client: ApiClient) -> list[dict[str, Any]]:
    return client.request("GET", "/stubs")["ui"]


def find_stub(client: ApiClient, rule_id: str) -> dict[str, Any]:
    rule = next((item for item in list_ui_stubs(client) if item["id"] == rule_id), None)
    if rule is None:
        raise ValueError(f"UI stub rule {rule_id} was not found")
    return rule


def redact_detail(detail: dict[str, Any], include_body: bool, show_sensitive: bool) -> dict[str, Any]:
    result = copy.deepcopy(detail)
    if not show_sensitive:
        for key in ("request_headers", "response_headers"):
            result[key] = [
                [name, "[REDACTED]" if name.lower() in SENSITIVE_HEADERS else value]
                for name, value in result.get(key, [])
            ]
    if not include_body:
        for key in ("request_body", "response_body", "request_body_image", "response_body_image"):
            if key in result:
                result[key] = "[OMITTED]"
    return result


def add_common_connection_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--base-url", default=os.getenv("MITM_BASE_URL"), help="Service origin or MITM_BASE_URL")
    parser.add_argument("--username", default=os.getenv("MITM_USERNAME"), help="Basic Auth user or MITM_USERNAME")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--timeout", type=float, default=15.0, help="Request timeout in seconds")
    parser.add_argument("--compact", action="store_true", help="Emit compact JSON")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    add_common_connection_arguments(parser)
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("status", help="Show settings, targets, and stub counts")

    targets = commands.add_parser("targets", help="Manage MITM domain suffixes").add_subparsers(
        dest="action", required=True
    )
    targets.add_parser("list")
    target_add = targets.add_parser("add")
    target_add.add_argument("suffix")
    for action in ("enable", "disable", "delete"):
        target = targets.add_parser(action)
        target.add_argument("id", type=int)

    capture = commands.add_parser("capture", help="Manage plaintext capture").add_subparsers(
        dest="action", required=True
    )
    for action in ("status", "on", "off"):
        capture.add_parser(action)

    stubs = commands.add_parser("stubs", help="Manage UI stub rules").add_subparsers(
        dest="action", required=True
    )
    stubs.add_parser("list")
    stub_get = stubs.add_parser("get")
    stub_get.add_argument("id")
    for action in ("add",):
        stub = stubs.add_parser(action)
        stub.add_argument("--file", required=True)
    stub_update = stubs.add_parser("update")
    stub_update.add_argument("id")
    stub_update.add_argument("--file", required=True)
    for action in ("enable", "disable", "delete"):
        stub = stubs.add_parser(action)
        stub.add_argument("id")
    stub_reorder = stubs.add_parser("reorder")
    stub_reorder.add_argument("ids", nargs="+")
    stub_match = stubs.add_parser("match")
    stub_match.add_argument("url")

    records = commands.add_parser("records", help="Filter and inspect captured records").add_subparsers(
        dest="action", required=True
    )
    record_list = records.add_parser("list")
    record_list.add_argument("--host")
    record_list.add_argument("--path")
    record_list.add_argument("--method")
    record_list.add_argument("--status", type=int)
    record_list.add_argument("--client-ip")
    record_list.add_argument("--query")
    record_list.add_argument("--limit", type=int, default=100)
    record_list.add_argument("--before", type=int)
    record_get = records.add_parser("get")
    record_get.add_argument("id")
    record_get.add_argument("--include-body", action="store_true")
    record_get.add_argument("--show-sensitive", action="store_true")
    return parser


def execute(client: ApiClient, args: argparse.Namespace) -> Any:
    if args.command == "status":
        settings = client.request("GET", "/settings")
        targets = client.request("GET", "/targets")
        stubs = client.request("GET", "/stubs")
        return {
            "origin": client.base_url,
            "settings": settings,
            "targets": targets,
            "stub_counts": {"file": len(stubs["file"]), "ui": len(stubs["ui"])},
        }

    if args.command == "targets":
        if args.action == "list":
            return client.request("GET", "/targets")
        if args.action == "add":
            return client.request("POST", "/targets", {"suffix": args.suffix})
        target = find_target(client, args.id)
        if args.action == "delete":
            client.request("DELETE", f"/targets/{args.id}")
            return {"deleted": args.id, "suffix": target["suffix"]}
        enabled = args.action == "enable"
        return client.request("PATCH", f"/targets/{args.id}", {"enabled": enabled})

    if args.command == "capture":
        if args.action == "status":
            return client.request("GET", "/settings")
        enabled = args.action == "on"
        return client.request("PATCH", "/settings", {"capture_enabled": enabled})

    if args.command == "stubs":
        if args.action == "list":
            return client.request("GET", "/stubs")
        if args.action == "get":
            return find_stub(client, args.id)
        if args.action == "add":
            return client.request("POST", "/stubs", read_json(args.file))
        if args.action == "update":
            payload = read_json(args.file)
            if not isinstance(payload, dict):
                raise ValueError("stub payload must be a JSON object")
            payload["id"] = args.id
            return client.request("PUT", f"/stubs/{urllib.parse.quote(args.id, safe='')}", payload)
        if args.action in {"enable", "disable"}:
            rule = find_stub(client, args.id)
            rule["enabled"] = args.action == "enable"
            return client.request("PUT", f"/stubs/{urllib.parse.quote(args.id, safe='')}", rule)
        if args.action == "delete":
            rule = find_stub(client, args.id)
            client.request("DELETE", f"/stubs/{urllib.parse.quote(args.id, safe='')}")
            return {"deleted": args.id, "note": rule.get("note", "")}
        if args.action == "reorder":
            current_ids = [rule["id"] for rule in list_ui_stubs(client)]
            if len(args.ids) != len(current_ids) or set(args.ids) != set(current_ids):
                raise ValueError("reorder requires every current UI stub rule ID exactly once")
            client.request("PUT", "/stubs/order", args.ids)
            return {"order": args.ids}
        return client.request("GET", "/stubs/match", query={"url": args.url})

    if args.command == "records":
        if args.action == "list":
            return client.request(
                "GET",
                "/records",
                query={
                    "host": args.host,
                    "path": args.path,
                    "method": args.method,
                    "status": args.status,
                    "client_ip": args.client_ip,
                    "q": args.query,
                    "limit": args.limit,
                    "before": args.before,
                },
            )
        detail = client.request("GET", f"/records/{urllib.parse.quote(args.id, safe='')}")
        return redact_detail(detail, args.include_body, args.show_sensitive)

    raise ValueError(f"unsupported command: {args.command}")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not args.base_url:
        parser.error("--base-url or MITM_BASE_URL is required")
    try:
        client = ApiClient(
            args.base_url,
            args.username,
            os.getenv("MITM_PASSWORD"),
            args.insecure,
            args.timeout,
        )
        print_json(execute(client, args), args.compact)
        return 0
    except (RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
