# costwright — MCP server

**Static worst-case token-budget analysis for LLM-agent workflows.** Point it at a Python repo
using LangGraph / CrewAI / OpenAI-Agents-SDK and it reports — by pure AST analysis, **without
running the code** — the worst-case budget ceiling of every workflow graph: which units are
*certifiable / default-dependent / non-certifiable / runaway*, and which LLM calls have no token
cap. Optionally issues an Ed25519-**signed budget certificate** logged to a public transparency log.
Wraps the hosted [costwright](https://eleata.io) API; backed by a Lean 4 cost-soundness theorem.

> Use it before deploying an agent workflow to catch missing token caps and `while True:` runaway
> drivers — the budget version of a type check.

## Tools

| Tool | What it does | Key? |
|------|--------------|------|
| `costwright_check(repo_path, policy?)` | Static budget analysis of a local repo. Returns pass/fail + counts of certifiable/default-dependent/non-certifiable/runaway units. | yes |
| `costwright_certify(repo_path, policy?, label?)` | Issues a signed, logged budget certificate. Returns cert_id + signature + verify_url. | yes |
| `costwright_verify(cert_id)` | Verify a certificate by id (valid/expired/revoked, signature check). | **public** |
| `costwright_pubkey()` | Active Ed25519 public keys for offline verification. | **public** |

## Setup

```json
{
  "mcpServers": {
    "costwright": {
      "command": "npx",
      "args": ["-y", "costwright-mcp"],
      "env": { "COSTWRIGHT_API_KEY": "your_rapidapi_key" }
    }
  }
}
```

The key is sent as `X-RapidAPI-Key` (RapidAPI channel) by default; set `COSTWRIGHT_DIRECT=1` to send
it as `Authorization: Bearer` for the direct channel. `verify` and `pubkey` work with no key.

`check`/`certify` build a `.py`-only gzip archive of `repo_path` client-side (excluding venv,
node_modules, tests, etc.) and send it for analysis — your source is uploaded to the hosted API.
See <https://eleata.io/privacy/>. MIT licensed.
