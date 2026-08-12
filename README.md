# AI & MCP Discovery — Nmap NSE Scripts

Two Nmap Scripting Engine scripts for discovering and enumerating AI infrastructure on a network.

| Script | Purpose | Mode |
|--------|---------|------|
| `http-ai-enum.nse` | Broad discovery — 60+ AI/MCP service types via HTTP probing | passive (GET) + optional active POST |
| `http-mcp-enum.nse` | Deep MCP enumeration — full JSON-RPC handshake, tools, resources, prompts | active |

Both scripts are categorized `safe` in Nmap's script database. They make only standard HTTP GET and POST requests; no exploit attempts, no destructive operations.

---

## Requirements

- Nmap 7.80 or later
- No external dependencies — both scripts use only standard NSE libraries (`http`, `nmap`, `shortport`, `stdnse`, `base64`)

---

## Installation

### Option A — Reference by path (no install needed)

```bash
nmap --script /path/to/http-ai-enum.nse <target>
nmap --script /path/to/http-mcp-enum.nse <target>
```

### Option B — Install into Nmap's script directory (recommended)

```bash
sudo cp http-ai-enum.nse http-mcp-enum.nse /usr/share/nmap/scripts/
sudo nmap --script-updatedb
```

After updating the database you can use the short names:

```bash
nmap --script http-ai-enum <target>
nmap --script http-mcp-enum <target>
```

Find your Nmap scripts directory if it differs from `/usr/share/nmap/scripts/`:

```bash
find /usr /opt -name "http-title.nse" 2>/dev/null | head -1 | xargs dirname
```

---

## http-ai-enum.nse

Discovers AI inference servers, model APIs, vector databases, ML platforms, observability tools, and MCP servers by probing HTTP endpoints. Uses per-port request caching so paths hit by multiple probes are only fetched once, keeping total requests well below the probe count.

When a specific service is confidently identified, its name is written into the nmap port table (the `VERSION` column) so it appears in normal scan output alongside the script results.

When an MCP server is found, its endpoint path is shared with `http-mcp-enum.nse` via the nmap script registry so the deep enumeration script skips its discovery phase on that port.

### Detected services

| Category | Services |
|----------|---------|
| Inference servers | Ollama, llama.cpp server, LM Studio, vLLM, LocalAI, LiteLLM, KoboldCPP, Text Generation WebUI, Tabby, TabbyAPI, Jan, GPT4All, HuggingFace TGI, HuggingFace TEI, Triton Inference Server, TorchServe, BentoML, Gradio, Aphrodite Engine, SGLang, Xinference, NVIDIA NIM, FauxPilot |
| Image generation | AUTOMATIC1111 (Stable Diffusion WebUI), InvokeAI, SwarmUI |
| Embeddings | Infinity (Embeddings), Marqo |
| Frontends / UIs | Open WebUI, AnythingLLM, ComfyUI, Flowise, Langflow, SillyTavern, LibreChat, Dify, Chainlit |
| Observability | Langfuse, Arize Phoenix |
| Speech / TTS | Whisper-compatible STT servers, Coqui TTS, AllTalk TTS |
| RAG infrastructure | Unstructured API |
| OpenAI-compatible | Any server exposing `/v1/models` (fingerprinted against known servers) |
| FastAPI catch-all | Any FastAPI service with AI-related paths or title in `/openapi.json` |
| Vector databases | ChromaDB, Qdrant, Weaviate, Milvus, Typesense |
| ML platforms | MLflow, Jupyter, Ray Dashboard, TensorBoard, n8n, Determined AI, ClearML |
| GPU / infra | NVIDIA DCGM Exporter, generic AI Prometheus metrics (vLLM, llama.cpp, SGLang, etc.) |
| Model files | Directory listings exposing `.gguf`, `.safetensors`, `.onnx` model weights |
| MCP | Model Context Protocol servers — header detection, `.well-known/mcp`, SSE transport, JSON-RPC `initialize` (active POST, disableable) |

### Security signals

Each finding reports:

- `security: UNAUTHENTICATED` — service responded without credentials
- `security: 401 Unauthorized` — service requires authentication
- `security: 403 Forbidden` — access denied
- `CORS:*` appended when `Access-Control-Allow-Origin: *` is set — any browser origin can call the API

### Script arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `http-ai-enum.timeout=N` | 4000 | Per-request HTTP timeout in milliseconds |
| `http-ai-enum.no_post=1` | off | Disable the active MCP JSON-RPC `initialize` probe (POST requests only; all GET probes still run) |
| `http-ai-enum.max_models=N` | 5 | Maximum number of model names to list per service |

### Usage

```bash
# Fast scan — known AI ports only
nmap -sV -p 1234,1337,3000,3001,4000,5000,5001,5002,5678,6006,6333,7851,7860,8000,8080,8108,8188,8888,9400,11434 \
     --script http-ai-enum <target>

# Full port sweep
nmap -sV -p- --script http-ai-enum <target>

# Passive only — no POST requests
nmap -sV --script http-ai-enum --script-args http-ai-enum.no_post=1 <target>

# Show more models, longer timeout
nmap -sV --script http-ai-enum --script-args http-ai-enum.max_models=20,http-ai-enum.timeout=8000 <target>
```

### Example output

```
PORT      STATE SERVICE  VERSION
11434/tcp open  http     Ollama
| http-ai-enum:
|   Ollama:
|     path: /api/tags, /api/version
|     security: UNAUTHENTICATED  CORS:*
|     version: 0.3.12
|_    models: llama3.2:latest, mistral:7b, codellama:13b (+4 more)

PORT     STATE SERVICE
3001/tcp open  http
| http-ai-enum:
|   MCP Server:
|     path: /mcp
|     security: UNAUTHENTICATED
|_    note: responded to initialize  capabilities: tools,resources,prompts
```

---

## http-mcp-enum.nse

Actively probes Model Context Protocol servers to perform the full JSON-RPC handshake and enumerate everything the server exposes: tools (with input schemas), static resources, URI template resources, and prompts (with template text).

When run alongside `http-ai-enum.nse` (using `--script http-ai-enum,http-mcp-enum`), the scripts share state — `http-ai-enum` identifies the MCP endpoint and `http-mcp-enum` uses it directly, skipping the discovery phase. To guarantee this ordering, `http-mcp-enum.nse` declares a dependency on `http-ai-enum.nse`.

### Transport support

Tried in order:

1. **`.well-known/mcp`** — reads the server's canonical endpoint path and transport type before guessing
2. **Streamable HTTP** — POST to `/mcp`, `/`, `/rpc`, `/api`, `/v1`. The 2026-07-28 stateless protocol is tried first on each candidate endpoint, falling back to the legacy stateful handshake
3. **SSE (legacy)** — GET `/sse`, `/events`, `/stream`, `/v1/sse`, `/api/sse`, `/mcp/sse`, `/mcp/stream` to discover the message endpoint, then POST to it (legacy stateful protocol only — there is no SSE-discovery equivalent under the stateless protocol). Handles both response styles a server may use: synchronous (the JSON-RPC reply comes back in the POST response) and async-push (the POST returns a bare `202 Accepted`, and the reply arrives as a later event pushed on the original SSE stream instead — this connection is kept open via a raw socket for exactly that purpose, including through `call=1`/`read=1`)

### Protocol version fallback

**2026-07-28 (stateless, tried first):** No `initialize`/session. Bootstraps directly with a `tools/list` call carrying `protocolVersion`, `clientCapabilities`, and `clientInfo` in the request's `_meta` field, plus `Mcp-Method`/`Mcp-Name`/`MCP-Protocol-Version` HTTP headers. Server identity comes from `_meta["io.modelcontextprotocol/serverInfo"]` in the response, since there's no `initialize` response to read it from. A rejected bootstrap (JSON-RPC error `-32020`, `-32021`, or `-32022` — all new in this spec revision) is itself treated as proof of a 2026-07-28 server and reported as a `note`, since those codes didn't exist before.

**Legacy stateful (fallback):** Sends `initialize` with protocol version `2025-11-25` first. If the server returns a JSON-RPC error, retries automatically with `2025-03-26`, then `2024-11-05`.

### What gets enumerated

- **Tools** — name, description, required parameters extracted from `inputSchema`
- **Resources** — static URIs with human-readable names
- **Resource templates** — RFC 6570 URI patterns (e.g. `file:///{path}`, `db://{table}/{id}`) that reveal what the server can serve on demand
- **Prompts** — names, descriptions, argument schemas (required args annotated with `*`), and template text via `prompts/get`
- **Capabilities** — full capability set from the `initialize` response (legacy stateful protocol only — Roots/Sampling/Logging capability negotiation is deprecated under the 2026-07-28 stateless protocol)
- **Session ID** — for Streamable HTTP stateful sessions (legacy protocol only; the 2026-07-28 stateless protocol has no session)

All list methods are paginated (`nextCursor` followed for up to `max_pages` pages per method).

### Security signals

| Signal | Meaning |
|--------|---------|
| `auth: UNAUTHENTICATED` | Server responded to `initialize` without credentials |
| `auth: AUTHENTICATED` | Credentials were supplied and the server responded 200 |
| `auth: 401 Unauthorized — Bearer required` | Confirmed MCP server behind auth; scheme from `WWW-Authenticate` |
| `CORS:*` | `Access-Control-Allow-Origin: *` on the MCP endpoint — any web origin can call this server |
| `WARNING: ...unsolicited sampling/createMessage...` | Server attempted to invoke an LLM completion through us despite never being granted sampling support — a protocol violation, and a real attempt (not just a declared capability) to consume the client's API credits or exfiltrate context. Checked on every `prompts/get` call (runs by default) and, with `call=1`/`read=1`, on every tool call and resource read. |
| `capability notes: logging` | Server can push log messages to connected clients |
| `capability notes: completions` | Argument autocompletion reveals valid parameter values |
| `needs further input: <method>` | A tool call, resource read, or prompt fetch was interrupted by a server-initiated request (e.g. `elicitation/create`) instead of completing — reported rather than silently dropped; the round-trip itself isn't attempted |

### Script arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `http-mcp-enum.timeout=N` | 6000 | Per-request HTTP timeout in milliseconds |
| `http-mcp-enum.call=1` | off | Actually calls every discovered tool (not just lists it), using its required parameter names as keys with empty string values. Empty strings usually pass argument-*presence* validation but not deeper checks, so the call proceeds into real tool logic and the response often reveals more than the tool's description did — SQL errors exposing schema, a secret handed back with no auth check, a server-initiated request the tool needed to complete (reported as `needs further input: <method>`). Result is shown in each tool's `call` field. |
| `http-mcp-enum.read=1` | off | Reads the content of the first three discovered resources via `resources/read` and shows a preview, so you can see what a resource actually contains rather than just its name/URI. |
| `http-mcp-enum.max_tools=N` | unlimited | Maximum number of tools to display |
| `http-mcp-enum.max_pages=N` | 5 | Maximum pagination pages to follow per list method |
| `http-mcp-enum.token=VALUE` | — | Bearer token — sends `Authorization: Bearer VALUE` on all requests |
| `http-mcp-enum.header=NAME:VALUE` | — | Arbitrary header for API key schemes (e.g. `X-Api-Key:secret`) |
| `http-mcp-enum.basic=USER:PASS` | — | HTTP Basic auth — base64-encodes `USER:PASS` automatically |

When credentials are supplied and the server responds with 200, `auth` changes from `UNAUTHENTICATED` to `AUTHENTICATED`.

### Usage

```bash
# Common MCP ports
nmap -sV -p 3000,3001,8000,8080,8443,9000,9001 --script http-mcp-enum <target>

# Full port sweep
nmap -sV -p- --script http-mcp-enum <target>

# Full active enumeration — call tools and read resources
nmap -sV --script http-mcp-enum --script-args http-mcp-enum.call=1,http-mcp-enum.read=1 <target>

# Follow more pagination pages (useful for servers with large tool sets)
nmap -sV --script http-mcp-enum --script-args http-mcp-enum.max_pages=20 <target>

# Enumerate a server behind Bearer token auth
nmap -sV --script http-mcp-enum --script-args http-mcp-enum.token=eyJhbG... <target>

# API key header auth
nmap -sV --script http-mcp-enum --script-args "http-mcp-enum.header=X-Api-Key:secret" <target>

# HTTP Basic auth
nmap -sV --script http-mcp-enum --script-args "http-mcp-enum.basic=admin:password" <target>
```

### Example output

```
PORT     STATE SERVICE
3001/tcp open  http
| http-mcp-enum:
|   server: MyApp MCP Gateway v1.2.0
|   transport: streamable-http
|   endpoint: /mcp
|   auth: UNAUTHENTICATED  CORS:*
|   protocol: 2025-03-26
|   capabilities: prompts, resources, tools
|   tools (12):
|     read_file:
|       description: Read the contents of a file from the filesystem
|       params (required): path
|       call: error: path "" is not a valid file path
|     execute_bash:
|       description: Execute a shell command and return stdout/stderr
|       params (required): command
|       call: ok: (empty command, no output)
|   resources (4):
|     file:///home/app/config.yaml: Application config
|     file:///var/log/app.log: Application log
|   resource templates (2):
|     file:///{path}: File System — Read any file by absolute path
|     s3://{bucket}/{key}: S3 Object — Read objects from S3
|   prompts (1):
|     system_prompt:
|       description: Default system prompt for the assistant
|_      template: You are a helpful assistant with access to the filesystem...
```

A 2026-07-28 stateless server looks the same but with no `session_id` or `capabilities`, and a distinct `transport` label. This example is real output captured against a genuine 2026-07-28-only test server — not illustrative like the one above — which is also why there's no `server:` line: this particular server doesn't populate `_meta.serverInfo` in its responses, and the script has nothing to fall back on since there's no `initialize` response under this protocol to read a name from:

```
PORT     STATE SERVICE
3001/tcp open  http
| http-mcp-enum:
|   transport: streamable-http (stateless, 2026-07-28)
|   endpoint: /mcp
|   auth: UNAUTHENTICATED
|   protocol: 2026-07-28
|   tools (2):
|     get_status:
|       description: Return service status.
|       call: ok: ok
|     link_account:
|       description: Link an external account.
|_      call: ok
```

---

## Running both scripts together

`http-ai-enum.nse` is a good first pass across a wide port range — it identifies service types quickly with minimal requests. When it finds an MCP server, `http-mcp-enum.nse` performs the full enumeration on that port.

Run them together and `http-ai-enum` automatically hands off the discovered endpoint to `http-mcp-enum` via shared state:

```bash
# Both scripts, known AI+MCP ports
nmap -sV -p 80,443,3000,3001,8000,8080,8443,9000,9001,11434 \
     --script http-ai-enum,http-mcp-enum \
     10.0.0.0/24

# Full active enumeration — call tools and read resources
nmap -sV -p 80,443,3000,3001,8000,8080,8443,9000,9001,11434 \
     --script http-ai-enum,http-mcp-enum \
     --script-args http-mcp-enum.call=1,http-mcp-enum.read=1 \
     10.0.0.0/24
```

Or as a two-step workflow:

```bash
# Step 1 — broad discovery across subnet
nmap -sV -p- --script http-ai-enum 10.0.0.0/24 -oG ai-scan.gnmap

# Step 2 — deep MCP enumeration on confirmed hosts/ports
nmap -sV -p 3001 --script http-mcp-enum \
     --script-args http-mcp-enum.call=1,http-mcp-enum.read=1 \
     10.0.0.42
```

---

## Output formats

Nmap's `-oN`, `-oX`, and `-oG` flags all capture NSE output:

```bash
# Normal output to file
nmap --script http-ai-enum -oN ai-scan.txt <target>

# Grepable output
nmap --script http-ai-enum -oG ai-scan.gnmap <target>
grep "http-ai-enum" ai-scan.gnmap

# XML output for post-processing
nmap --script http-mcp-enum -oX mcp-scan.xml <target>
```

---

## Notes

- `http-mcp-enum.call=1` sends real tool invocations with empty argument values — this is active probing, not passive listing. On a tool with no required parameters, or one that only checks argument presence, the call can execute for real rather than just fail validation; on strictly-validated tools it usually surfaces a validation error instead, which is still useful (e.g. confirms the parameter is server-side-enforced). Either way, something the tool's static description didn't say gets surfaced. Use with appropriate authorization.
- `http-mcp-enum.read=1` reads resources the server has already listed as accessible. It does not attempt to read resources outside the server's advertised list.
- The MCP probe in `http-ai-enum.nse` sends a POST `initialize` request to confirm MCP servers. Use `http-ai-enum.no_post=1` if POST requests are not acceptable in your environment — all GET-based probes still run.
