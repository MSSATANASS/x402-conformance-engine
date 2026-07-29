# x402-conformance-suite

Audit, monitor, and protect endpoints against the **x402 strict-v2** standard.

```bash
pip install x402-conformance-suite
```

## Quick examples

CLI:
```bash
x402-validate https://observer.137-184-67-179.sslip.io
```

Batch audit:
```bash
x402-validate endpoints.txt --output html --parallel 20
```

MCP server (Claude / Cursor / any MCP client):
```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | x402-mcp
```

Python:
```python
import asyncio
from x402_conformance_suite._engine import run_audit

async def main():
    report = await run_audit("https://example.com")
    print(report.summary)

asyncio.run(main())
```

## What it checks

Seven core checks plus marketplace mode:

| Check                        | Purpose                                                                 |
|------------------------------|-------------------------------------------------------------------------|
| `manifest_discovery`         | `GET /.well-known/x402` returns a valid JSON manifest                    |
| `caip2_compliance`           | A valid CAIP-2 network is advertised — including v2 `accepts[].network`  |
| `json_resilience`            | HTTP 402 body is a JSON object, not a primitive                          |
| `bazaar_compliance`          | The 402 body has a valid `extensions.bazaar` block                       |
| `bot_wall`                   | No bot-protection challenge answers in place of the origin               |
| `accepts_completeness`       | Every `accepts[]` entry is complete, with amounts in atomic units        |
| `discovery_resource_listing` | The paid resource is listed in the origin's catalog so agents find it    |

A check that does not apply — a bazaar block on an endpoint that never returns
402, say — reports PASS with `applicable: false` rather than punishing the
operator for something the spec does not require.

For multi-product catalogs, use `mode="marketplace"`: every product in the
manifest gets its own endpoint audit and bazaar check (see
[API.md](docs/API.md)).

## Extended tools (separate repo)

Dashboard, API server, Stripe monetization, and proxy middleware:
[MSSATANASS/x402-validator-tools](https://github.com/MSSATANASS/x402-validator-tools)

## Documentation

- [API Reference](docs/API.md) — every public function and result type
- [Design](docs/DESIGN.md) — architecture and design choices
- [Validation Report](docs/VALIDATION_REPORT_v0.3.md) — 27 endpoints audited in 5.2 s
- [Contributing](CONTRIBUTING.md) — how to add checks without breaking stability

## License

Apache-2.0.
