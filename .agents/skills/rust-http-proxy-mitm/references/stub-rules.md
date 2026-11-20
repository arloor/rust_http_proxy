# Stub Rule Payloads

Use these payloads with the portable `scripts/mitm_control.py` client.

The management API stores UI rules. File-backed rules returned by `stubs list`
are read-only.

## Common fields

Every add or update payload is a complete rule:

```json
{
  "id": "",
  "note": "Neutral description",
  "enabled": true,
  "match_type": "exact",
  "authority": "api.example.com:443",
  "path": "/v1/profile",
  "url_pattern": "",
  "mode": "response",
  "body": "{\"result\":\"stubbed\"}",
  "status": 200,
  "upstream": null,
  "request_headers": [],
  "response_headers": [
    {
      "enabled": true,
      "op": "set",
      "note": "",
      "name": "content-type",
      "value": "application/json"
    }
  ]
}
```

For a new rule, use an empty `id`; the server assigns it. For updates, start
from the object returned by `stubs list` and retain its `id`.

## Match types

`exact` matches CONNECT authority plus path and ignores query:

```json
{
  "match_type": "exact",
  "authority": "api.example.com:443",
  "path": "/v1/profile",
  "url_pattern": ""
}
```

The authority must include a port. The path starts with `/` and contains no
query or fragment.

`regex` matches the complete HTTPS URL, including query:

```json
{
  "match_type": "regex",
  "authority": "",
  "path": "",
  "url_pattern": "^https://api\\.example\\.com/v1/items/[0-9]+\\?view=full$"
}
```

Rust regex syntax is used. Matching is case-sensitive unless the expression
contains `(?i)`. Anchors are not added automatically.

## Modes

### Static response

Set `mode` to `response`, provide `body` and `status`, and set `upstream` to
`null`. Status must be 200 through 599. Status 204, 205, and 304 require an
empty body. Body size is limited to 1 MiB.

### Alternate upstream

```json
{
  "mode": "upstream",
  "body": "",
  "status": null,
  "upstream": "http://127.0.0.1:9010/stub"
}
```

The original path and query are appended to the upstream prefix. Only HTTP and
HTTPS URLs are accepted.

### Header-only original service

```json
{
  "mode": "headers",
  "body": "",
  "status": null,
  "upstream": null,
  "request_headers": [
    {
      "enabled": true,
      "op": "set",
      "note": "",
      "name": "x-test-mode",
      "value": "stub"
    }
  ],
  "response_headers": []
}
```

At least one request or response header operation is required. Operations are
`add`, `set`, or `remove`. For `remove`, use an empty `value`. A rule supports
at most 100 operations in total.

Transport-managed headers such as `Host`, `Content-Length`,
`Transfer-Encoding`, `Connection`, `Upgrade`, proxy authentication headers,
and other hop-by-hop headers cannot be changed.

## Execution behavior

Rules execute in this order:

1. Read-only configuration-file rules.
2. Enabled UI rules in stored order.

The first matching static-response or alternate-upstream rule decides the
response. Later response-producing rules are shadowed. Matching header-only
rules continue to accumulate changes. Use `stubs match URL` after mutation to
inspect the effective order and verdicts.
