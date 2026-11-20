---
name: rust-http-proxy-mitm
description: Manage rust_http_proxy MITM targets, stub rules, plaintext capture, and captured-record filters. Use for configuring or inspecting this repository's MITM service.
---

# rust_http_proxy MITM Control

Operate the running service through its `/mitm/api` management endpoints. Use
`scripts/mitm_control.py` instead of assembling HTTP requests by hand.
Resolve `SKILL_SCRIPT` to the absolute path of
`scripts/mitm_control.py` relative to this `SKILL.md`; do not assume the
current working directory is the repository or the installed skill directory.

## Establish the connection

1. Resolve the service origin from the user's explicit URL or the active
   project configuration. The origin is `http(s)://host:port`, without
   `/mitm`.
2. Do not scan hosts or ports. Ask for the origin only when it cannot be
   discovered safely.
3. Pass credentials through `MITM_USERNAME` and `MITM_PASSWORD`; never place
   the password in a command argument, source file, report, or chat response.
4. Keep TLS verification enabled. Use `--insecure` only when the user
   explicitly authorizes a known development or self-signed endpoint.
5. Run `status` before mutations. A `401` means the management credentials are
   absent or invalid.

Use the Python executable available in the environment:

```sh
python SKILL_SCRIPT --base-url https://127.0.0.1:444 status
```

## Domain suffixes

List targets before changing them:

```sh
python SKILL_SCRIPT --base-url URL targets list
python SKILL_SCRIPT --base-url URL targets add example.com
python SKILL_SCRIPT --base-url URL targets disable TARGET_ID
python SKILL_SCRIPT --base-url URL targets enable TARGET_ID
```

Suffixes are case-normalized and match the suffix itself plus subdomains.
Changes affect new connections only. Targets marked `cli_managed` come from
`--mitm-domain-suffix`; do not claim that deleting them through the API is
possible. Removing those requires changing startup arguments and restarting,
which is outside this workflow unless the user explicitly requests it.

Delete a dynamic target only when the user explicitly requests deletion:

```sh
python SKILL_SCRIPT --base-url URL targets delete TARGET_ID
```

## Plaintext capture

Inspect settings, then apply the requested state:

```sh
python SKILL_SCRIPT --base-url URL capture status
python SKILL_SCRIPT --base-url URL capture on
python SKILL_SCRIPT --base-url URL capture off
```

If `capture_cli_managed` is true, `--mitm-dump` locks capture on. Explain that
the startup argument and process restart must be handled separately. Turning
capture off does not disable Stub rules.

## Stub rules

Read [references/stub-rules.md](references/stub-rules.md) before creating or
updating a rule. Use a temporary JSON file outside the repository for request
payloads unless the user asks to save a reusable fixture.

```sh
python SKILL_SCRIPT --base-url URL stubs list
python SKILL_SCRIPT --base-url URL stubs get RULE_ID
python SKILL_SCRIPT --base-url URL stubs add --file RULE.json
python SKILL_SCRIPT --base-url URL stubs update RULE_ID --file RULE.json
python SKILL_SCRIPT --base-url URL stubs disable RULE_ID
python SKILL_SCRIPT --base-url URL stubs enable RULE_ID
python SKILL_SCRIPT --base-url URL stubs reorder RULE_ID_1 RULE_ID_2
python SKILL_SCRIPT --base-url URL stubs match 'https://api.example.com/v1/profile'
```

Updates are full replacements, not patches. Fetch the current rule first and
preserve fields the user did not ask to change. Reordering requires every UI
rule ID exactly once and is applied atomically. After add, update, enable,
disable, or reorder, run `stubs match` with a representative URL and report
`decided_by` plus the relevant verdict. Configuration-file rules are read-only
and execute before UI rules.

Delete a UI rule only on an explicit request:

```sh
python SKILL_SCRIPT --base-url URL stubs delete RULE_ID
```

## Filter captured records

Start with summaries. Combine exact filters as needed:

```sh
python SKILL_SCRIPT --base-url URL records list --host api.example.com --path /v1/profile --method GET --status 200 --client-ip 127.0.0.1 --query profile --limit 50
```

`host`, `path`, `method`, `status`, and `client-ip` are exact filters.
`--query` searches authority, path, and URL query text. `--before` paginates
using the returned `next_before`. Do not clear the record database as part of
filtering.

Fetch details only for IDs relevant to the request:

```sh
python SKILL_SCRIPT --base-url URL records get RECORD_ID
```

The default detail output omits bodies and redacts authentication and cookie
headers. Use `--include-body` only when body content is necessary, and
`--show-sensitive` only when the user explicitly requests raw sensitive
headers and the output destination is appropriate. Never repeat secrets in the
final response.

## Verify and report

After each mutation, fetch the affected resource again. Report the service
origin, resulting state or rule ID, and any restart or new-connection
requirement. Keep captured content out of the report unless the user asked for
specific matching data.
