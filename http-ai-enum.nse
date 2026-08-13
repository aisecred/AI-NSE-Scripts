local http      = require "http"
local nmap      = require "nmap"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local table     = require "table"

description = [[
Discovers AI inference servers, model APIs, vector databases, ML platforms,
and MCP (Model Context Protocol) servers on open HTTP ports.

Identified services:
  Inference:   Ollama, llama.cpp, LM Studio, vLLM, LocalAI, LiteLLM,
               KoboldCPP, Text Generation WebUI, Tabby, TabbyAPI, Jan,
               GPT4All, HuggingFace TGI, HuggingFace TEI, Triton Inference
               Server, TorchServe, BentoML, Gradio, Aphrodite Engine,
               SGLang, Xinference, NVIDIA NIM, FauxPilot,
               AUTOMATIC1111 (Stable Diffusion WebUI), InvokeAI, SwarmUI,
               Infinity (Embeddings), Marqo
  Frontends:   Open WebUI, AnythingLLM, ComfyUI, Flowise, Langflow,
               SillyTavern, LibreChat, Dify
  Compatible:  Any OpenAI-compatible /v1/models endpoint, FastAPI services
               exposing /openapi.json with AI-related paths
  Vector DBs:  ChromaDB, Qdrant, Weaviate, Milvus
  Platforms:   MLflow, Jupyter, Ray Dashboard, Ray Serve, TensorBoard, n8n
  GPU/Infra:   NVIDIA DCGM Exporter, generic AI Prometheus metrics
  Files:       Directory listings exposing .gguf / .safetensors / .onnx
               (checks /, /models, /weights, /checkpoints)
  Observability: Langfuse, Arize Phoenix
  Speech/TTS:  Whisper-compatible STT servers, Coqui TTS, AllTalk TTS
  RAG infra:   Unstructured API, Hayhooks (Haystack)
  ML Platforms: Determined AI, ClearML
  Chat UI:     Chainlit
  Search:      Typesense
  MCP:         Model Context Protocol servers (header + JSON-RPC + SSE)

Each finding reports: detected path(s), security state (auth + CORS),
version, and available models where the API exposes them.

Request caching: paths hit by multiple probes are only fetched once per
port, keeping total HTTP requests well below the probe count.

Script arguments:
  http-ai-enum.no_post=1    Disable active MCP JSON-RPC initialize probe (POST).
  http-ai-enum.timeout=N    Per-request HTTP timeout in milliseconds (default 4000).
  http-ai-enum.max_models=N Maximum number of models to list per service (default 5).

Usage:
  # Known AI ports — fast
  nmap -sV -p 1234,1337,3000,3001,4000,5000,5001,5678,6006,6333,7860, \
             8000,8080,8188,8888,9400,11434 \
       --script http-ai-enum <target>

  # Full sweep
  nmap -sV -p- --script http-ai-enum <target>

  # Passive only (no POST)
  nmap -sV --script http-ai-enum --script-args http-ai-enum.no_post=1 <target>
]]

author     = "find_all_ai"
license    = "Same as Nmap -- https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

-- Port rule

local _EXTRA_PORTS = {
  1234,   -- LM Studio
  1337,   -- Jan
  2242,   -- Aphrodite Engine
  3001,   -- AnythingLLM / various
  3080,   -- LibreChat
  4000,   -- LiteLLM
  4891,   -- GPT4All
  5000,   -- LocalAI, TabbyAPI, FauxPilot
  5001,   -- KoboldCPP alt
  5678,   -- n8n
  6006,   -- TensorBoard
  6333,   -- Qdrant HTTP
  7860,   -- Text Generation WebUI / Gradio / A1111
  7861,   -- Gradio alt
  8188,   -- ComfyUI
  8265,   -- Ray Dashboard
  7801,   -- SwarmUI
  7997,   -- Infinity (Embeddings)
  8108,   -- Typesense
  8882,   -- Marqo
  9001,   -- various
  9090,   -- InvokeAI
  9091,   -- Milvus HTTP / Prometheus
  9400,   -- NVIDIA DCGM Exporter
  5002,   -- Coqui TTS
  7851,   -- AllTalk TTS
  8008,   -- ClearML API (alt port)
  9997,   -- Xinference
  11434,  -- Ollama
  11435,  -- Ollama alt
  30000,  -- SGLang
  1416,   -- Hayhooks (Haystack pipelines)
}

portrule = function(host, port)
  if port.protocol ~= "tcp" or port.state ~= "open" then return false end
  if shortport.http(host, port) then return true end
  -- When -sV probed a port and got HTTP responses but nmap couldn't match a
  -- known service (leaving it as "exlm-agent?" etc.), the raw probe data is
  -- stored in port.version.service_fp. HTTP responses always contain "HTTP/1"
  -- or "HTTP/2", so checking there catches HTTP servers on non-standard ports
  -- that nmap's service DB doesn't recognize.
  local sfp = (port.version and port.version.service_fp or "")
  if sfp:find("HTTP/1", 1, true) or sfp:find("HTTP/2", 1, true) then return true end
  for _, p in ipairs(_EXTRA_PORTS) do
    if port.number == p then return true end
  end
  return false
end

-- Script args

local TIMEOUT     = tonumber(stdnse.get_script_args("http-ai-enum.timeout"))     or 4000
local NO_POST     = stdnse.get_script_args("http-ai-enum.no_post")
local MAX_MODELS  = tonumber(stdnse.get_script_args("http-ai-enum.max_models"))  or 5

-- Pure helpers (no host/port dependency)

local function has(s, pat)
  if not s or s == "" then return false end
  return s:lower():find(pat:lower(), 1, true) ~= nil
end

local function jstr(body, key)
  if not body then return nil end
  return body:match('"' .. key .. '"%s*:%s*"([^"]*)"')
end

local function jall(body, key)
  local t = {}
  if body then
    for v in body:gmatch('"' .. key .. '"%s*:%s*"([^"]*)"') do
      if v ~= "" then t[#t+1] = v end
    end
  end
  return t
end

local function hdr(r, name)
  if not r or not r.header then return "" end
  return r.header[name:lower()] or ""
end

local function auth_of(r)
  if not r then return nil end
  if r.status == 200 then return "UNAUTHENTICATED" end
  if r.status == 401 then return "401 Unauthorized" end
  if r.status == 403 then return "403 Forbidden" end
  return nil
end

-- Proxy guard: Burp/mitmproxy return 200 text/html for every path; JSON APIs never do.
local function is_html(r)
  return r and has(hdr(r, "content-type"), "text/html")
end

local function cors_open(r)
  local h = hdr(r, "access-control-allow-origin")
  return h == "*" or (h ~= "" and h:find("%*") ~= nil)
end

-- Probe definitions
-- Signature: function(cget, cpost) -> result | nil
-- cget/cpost are per-action closures with request caching (see action below).

local PROBES = {}

-- Ollama

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/api/tags")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if not has(r.body, '"models"') then return nil end
  return { service = "Ollama", path = "/api/tags",
           auth = auth_of(r), cors = cors_open(r),
           models = jall(r.body, "name") }
end

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/api/version")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  local ver = jstr(r.body, "version")
  -- Ollama payload is tiny (<80 bytes); skip larger generic /api/version responses
  if ver and #(r.body or "") < 80 then
    return { service = "Ollama", path = "/api/version",
             auth = auth_of(r), cors = cors_open(r), version = ver }
  end
end

-- llama.cpp server

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/props")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if not has(r.body, "default_generation_settings") then return nil end
  local model = jstr(r.body, "model_path") or jstr(r.body, "model")
  return { service = "llama.cpp server", path = "/props",
           auth = auth_of(r), cors = cors_open(r),
           models = model and {model} or nil }
end

-- HuggingFace TGI
-- /info has model_id + model_dtype; TEI has model_id + max_batch_tokens instead

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/info")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if not has(r.body, "model_id") or not has(r.body, "model_dtype") then return nil end
  if has(r.body, "max_batch_tokens") then return nil end  -- that's TEI, handled below
  local model = jstr(r.body, "model_id")
  local dtype = jstr(r.body, "model_dtype")
  return { service = "HuggingFace TGI", path = "/info",
           auth = auth_of(r), cors = cors_open(r),
           models = model and {model} or nil,
           note = dtype and ("dtype: " .. dtype) or nil }
end

-- HuggingFace TEI

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/info")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if not has(r.body, "model_id") or not has(r.body, "max_batch_tokens") then return nil end
  local model = jstr(r.body, "model_id")
  return { service = "HuggingFace TEI", path = "/info",
           auth = auth_of(r), cors = cors_open(r),
           models = model and {model} or nil }
end

-- Triton Inference Server

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/v2/health/ready")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  local meta = cget("/v2")  -- cached; free if already fetched
  if not meta or not has(meta.body, "triton") or is_html(meta) then return nil end
  local mr = cget("/v2/models")
  return { service = "Triton Inference Server", path = "/v2/health/ready",
           auth = auth_of(r), cors = cors_open(r),
           version = jstr(meta.body, "version"),
           models = mr and jall(mr.body, "name") or {} }
end

-- OpenAI-compatible /v1/models
-- Catches and fingerprints: Ollama, LM Studio, vLLM, LocalAI, LiteLLM,
-- Jan, TorchServe, GPT4All, and any other OpenAI-compat server.

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/v1/models")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if not has(r.body, '"data"') then return nil end

  local svc  = "OpenAI-compatible API"
  local body = (r.body or ""):lower()
  local srv  = hdr(r, "server"):lower()
  local xpby = hdr(r, "x-powered-by"):lower()

  if     has(srv,  "ollama")     or has(body, '"ollama"')     then svc = "Ollama"
  elseif has(body, "lm-studio")  or has(body, "lmstudio")
      or has(xpby, "lmstudio")                                then svc = "LM Studio"
  elseif has(body, '"vllm"')     or has(srv,  "vllm")         then svc = "vLLM"
  elseif has(xpby, "aphrodite")  or has(body, "aphrodite")    then svc = "Aphrodite Engine"
  elseif has(body, "localai")    or has(srv,  "localai")      then svc = "LocalAI"
  elseif has(body, "litellm")    or has(srv,  "litellm")      then svc = "LiteLLM"
  elseif has(body, '"tabby"')    or has(srv,  "tabby")        then svc = "Tabby"
  elseif has(body, '"jan"')      or has(xpby, "jan")          then svc = "Jan"
  elseif has(srv,  "torchserve") or has(body, "torchserve")   then svc = "TorchServe"
  elseif has(body, "gpt4all")    or has(srv,  "gpt4all")      then svc = "GPT4All"
  end

  return { service = svc, path = "/v1/models",
           auth = auth_of(r), cors = cors_open(r),
           models = jall(r.body, "id") }
end

-- LM Studio dedicated endpoint
-- /api/v0/models is unique to LM Studio and returns publisher + arch fields

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/api/v0/models")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if not has(r.body, "publisher") and not has(r.body, '"arch"') then return nil end
  return { service = "LM Studio", path = "/api/v0/models",
           auth = auth_of(r), cors = cors_open(r),
           models = jall(r.body, "id") }
end

-- KoboldCPP

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/api/v1/info")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if not has(r.body, "kobold") then return nil end
  return { service = "KoboldCPP", path = "/api/v1/info",
           auth = auth_of(r), cors = cors_open(r),
           version = jstr(r.body, "version") }
end

-- /api/v1/model is shared with Text Gen WebUI — check for oobabooga markers first
PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/api/v1/model")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if has(r.body, "oobabooga") or has(r.body, "text-generation-webui") then return nil end
  local model = jstr(r.body, "result")
  if model then
    return { service = "KoboldCPP", path = "/api/v1/model",
             auth = auth_of(r), cors = cors_open(r), models = {model} }
  end
end

-- Text Generation WebUI (oobabooga)

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/api/v1/model")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if has(r.body, "oobabooga") or has(r.body, "text-generation-webui") then
    return { service = "Text Generation WebUI", path = "/api/v1/model",
             auth = auth_of(r), cors = cors_open(r) }
  end
end

-- Tabby

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/v1/health")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if has(r.body, "tabby") or has(hdr(r, "server"), "tabby") then
    return { service = "Tabby", path = "/v1/health",
             auth = auth_of(r), cors = cors_open(r) }
  end
end

-- vLLM
-- Confirmed via vllm-namespaced Prometheus metric names on /metrics (cached)

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/metrics")
  if not r or r.status ~= 200 then return nil end
  if not has(r.body, "vllm:") and not has(r.body, "vllm_") then return nil end
  local ver = (r.body or ""):match('vllm_version="([^"]*)"')
  return { service = "vLLM", path = "/metrics",
           auth = auth_of(r), version = ver }
end

-- LocalAI

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/readyz")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if has(r.body, "localai") or has(hdr(r, "server"), "localai") then
    return { service = "LocalAI", path = "/readyz",
             auth = auth_of(r), cors = cors_open(r) }
  end
end

-- LiteLLM

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/health/liveliness")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if has(r.body, "liveliness") or has(r.body, "litellm") then
    return { service = "LiteLLM", path = "/health/liveliness",
             auth = auth_of(r), cors = cors_open(r) }
  end
end

-- Open WebUI
-- /api/models requires auth in Open WebUI >=0.4; /api/version is always public

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/api/models")
  if r and r.status == 200 and not is_html(r) then
    if has(r.body, "open-webui") or has(r.body, "openwebui")
    or has(hdr(r, "x-powered-by"), "open-webui") then
      return { service = "Open WebUI", path = "/api/models",
               auth = auth_of(r), cors = cors_open(r) }
    end
  end
  local vr = cget("/api/version")
  if vr and vr.status == 200 and not is_html(vr)
  and (has(vr.body, "open-webui") or has(vr.body, "openwebui")
  or has(hdr(vr, "x-powered-by"), "open-webui")) then
    return { service = "Open WebUI", path = "/api/version",
             auth = auth_of(vr), cors = cors_open(vr),
             version = jstr(vr.body, "version") }
  end
end

-- AnythingLLM
-- /api/v1/system exposes version + storage_type — more specific than /api/ping

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/api/v1/system")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if has(r.body, "anythingllm") or has(r.body, "vectordb")
  or (has(r.body, "version") and has(r.body, "storage_type")) then
    return { service = "AnythingLLM", path = "/api/v1/system",
             auth = auth_of(r), cors = cors_open(r),
             version = jstr(r.body, "version") }
  end
end

-- ComfyUI
-- /system_stats returns system + devices including vram_total and torch_version

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/system_stats")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if not has(r.body, "system") or not has(r.body, "devices") then return nil end
  if has(r.body, "comfyui") or has(r.body, "vram_total") or has(r.body, "torch_version") then
    -- Version may be a string or number; try both quote styles
    local ver = jstr(r.body, "comfyui")
             or (r.body or ""):match('"comfyui"%s*:%s*([%d%.]+)')
    return { service = "ComfyUI", path = "/system_stats",
             auth = auth_of(r), cors = cors_open(r), version = ver }
  end
end

-- Flowise
-- /api/v1/chatflows is 401 in default deployments; /api/v1/ping is always public

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/api/v1/chatflows")
  if r and r.status == 200 and not is_html(r)
  and (has(r.body, "chatflowType") or has(r.body, "flowData")
  or has(hdr(r, "server"), "flowise")) then
    return { service = "Flowise", path = "/api/v1/chatflows",
             auth = auth_of(r), cors = cors_open(r) }
  end
  local pr = cget("/api/v1/ping")
  if not pr or pr.status ~= 200 or is_html(pr) then return nil end
  if has(pr.body, '"pong"') or has(hdr(pr, "server"), "flowise")
  or has(hdr(pr, "x-powered-by"), "flowise") then
    local auth = (r and r.status == 401) and "401 Unauthorized" or auth_of(pr)
    return { service = "Flowise", path = "/api/v1/ping",
             auth = auth, cors = cors_open(pr) }
  end
end

-- Langflow

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/api/v1/health_check")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if has(r.body, "langflow") or has(hdr(r, "server"), "langflow") then
    return { service = "Langflow", path = "/api/v1/health_check",
             auth = auth_of(r), cors = cors_open(r) }
  end
end

-- Hayhooks (Haystack pipelines deployed as REST APIs)
-- /status is Hayhooks-specific: {"pipelines": [...], "status": "..."} — the
-- "pipelines" array is the distinguishing field, not just a generic "status" key.

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/status")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if not has(r.body, '"pipelines"') or not has(r.body, '"status"') then return nil end
  return { service = "Hayhooks (Haystack)", path = "/status",
           auth = auth_of(r), cors = cors_open(r) }
end

-- SillyTavern

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/api/app-version")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if has(r.body, "sillytavern") then
    return { service = "SillyTavern", path = "/api/app-version",
             auth = auth_of(r), cors = cors_open(r),
             version = jstr(r.body, "version") }
  end
end

-- BentoML

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/readyz")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if has(r.body, "bentoml") or has(hdr(r, "server"), "bentoml") then
    return { service = "BentoML", path = "/readyz",
             auth = auth_of(r), cors = cors_open(r) }
  end
end

-- Gradio
-- /config returns the full Gradio app config with components, theme, etc.

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/config")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if has(r.body, "gradio") or has(hdr(r, "server"), "gradio") then
    return { service = "Gradio", path = "/config",
             auth = auth_of(r), cors = cors_open(r),
             version = jstr(r.body, "version") }
  end
end

-- AUTOMATIC1111 / Stable Diffusion WebUI
-- Distinguished from Gradio by the sdapi namespace; Gradio probe covers /config

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/sdapi/v1/sd-models")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if not has(r.body, '"title"') and not has(r.body, '"model_name"') then return nil end
  local opts = cget("/sdapi/v1/options")
  local model = opts and jstr(opts.body, "sd_model_checkpoint")
  return { service = "AUTOMATIC1111 (Stable Diffusion WebUI)", path = "/sdapi/v1/sd-models",
           auth = auth_of(r), cors = cors_open(r),
           models = model and {model} or nil }
end

-- LibreChat
-- /api/endpoints returns {"openAI":..., "azureOpenAI":..., "anthropic":...}
-- requiring all three keys is specific enough to avoid generic hits

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/api/health")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if has(r.body, "librechat") or has(hdr(r, "server"), "librechat")
  or has(hdr(r, "x-powered-by"), "librechat") then
    return { service = "LibreChat", path = "/api/health",
             auth = auth_of(r), cors = cors_open(r),
             version = jstr(r.body, "version") }
  end
  local ep = cget("/api/endpoints")
  if ep and ep.status == 200 and not is_html(ep)
  and has(ep.body, '"openAI"') and has(ep.body, '"azureOpenAI"')
  and has(ep.body, '"anthropic"') then
    return { service = "LibreChat", path = "/api/health",
             auth = auth_of(r), cors = cors_open(r) }
  end
end

-- Aphrodite Engine
-- Catches header-only cases not fingerprinted by the OpenAI-compat probe

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/v1/models")
  if not r then return nil end
  if has(hdr(r, "x-powered-by"), "aphrodite") then
    return { service = "Aphrodite Engine", path = "/v1/models",
             auth = auth_of(r), cors = cors_open(r),
             models = r.status == 200 and jall(r.body, "id") or nil }
  end
end

-- SGLang
-- /get_model_info is SGLang-specific; /v1/models used by many, so avoid it here

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/get_model_info")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if not has(r.body, "model_path") and not has(r.body, '"tokenizer"') then return nil end
  local model = jstr(r.body, "model_path")
  return { service = "SGLang", path = "/get_model_info",
           auth = auth_of(r), cors = cors_open(r),
           models = model and {model} or nil }
end

-- Xinference

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/v1/cluster/info")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if not has(r.body, "xinference") and not has(r.body, "xorbits") then return nil end
  local version = jstr(r.body, "version")
  local mr = cget("/v1/models")
  return { service = "Xinference", path = "/v1/cluster/info",
           auth = auth_of(r), cors = cors_open(r),
           version = version,
           models = mr and mr.status == 200 and jall(mr.body, "id") or nil }
end

-- TabbyAPI
-- Returns a single model object with a parameters{} block — distinct from
-- the Tabby code-completion server which never has this shape.

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/v1/model")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if not has(r.body, '"parameters"') or not has(r.body, '"object"') then return nil end
  local model = jstr(r.body, "id")
  return { service = "TabbyAPI", path = "/v1/model",
           auth = auth_of(r), cors = cors_open(r),
           models = model and {model} or nil }
end

-- NVIDIA NIM
-- NIM implements both /v1/health/live and /v1/health/ready and returns JSON
-- (not an empty body like generic k8s probes). Both 200 + JSON = NIM.

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/v1/health/live")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if not has(r.body, '"') then return nil end  -- k8s probes return empty/text body
  local rr = cget("/v1/health/ready")
  if not rr or rr.status ~= 200 or is_html(rr) then return nil end
  local mr = cget("/v1/models")
  return { service = "NVIDIA NIM", path = "/v1/health/live",
           auth = auth_of(r), cors = cors_open(r),
           models = mr and mr.status == 200 and jall(mr.body, "id") or nil }
end

-- Dify
-- /api/info returns {"data":{"title":"Dify",...}}; /console/api/setup is unique

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/api/info")
  if r and r.status == 200 and not is_html(r) and has(r.body, "dify") then
    return { service = "Dify", path = "/api/info",
             auth = auth_of(r), cors = cors_open(r) }
  end
  local sr = cget("/console/api/setup")
  if sr and (sr.status == 200 or sr.status == 401) and not is_html(sr) and has(sr.body, "setup") then
    return { service = "Dify", path = "/console/api/setup",
             auth = auth_of(sr), cors = cors_open(sr) }
  end
end

-- InvokeAI
-- /api/v1/app/config has infill_methods / force_tiled_decode — unique to InvokeAI

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/api/v1/app/version")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if not has(r.body, '"version"') then return nil end
  local cr = cget("/api/v1/app/config")
  if cr and cr.status == 200 and not is_html(cr)
  and (has(cr.body, "infill_methods") or has(cr.body, "invokeai")
  or has(cr.body, "force_tiled_decode")) then
    return { service = "InvokeAI", path = "/api/v1/app/version",
             auth = auth_of(r), cors = cors_open(r),
             version = jstr(r.body, "version") }
  end
end

-- SwarmUI
-- /API/GetCurrentStatus is unique to SwarmUI (note capital API prefix)

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/API/GetCurrentStatus")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if has(r.body, "backend_status") or has(r.body, "swarmui")
  or has(r.body, "current_model") or has(r.body, "ModelName") then
    return { service = "SwarmUI", path = "/API/GetCurrentStatus",
             auth = auth_of(r), cors = cors_open(r) }
  end
end

-- Infinity (Embeddings)
-- queue_fraction in /models is unique to Infinity embedding server

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/models")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if has(r.body, "queue_fraction") then
    return { service = "Infinity (Embeddings)", path = "/models",
             auth = auth_of(r), cors = cors_open(r),
             models = jall(r.body, "id") }
  end
end

-- Marqo
-- /health returns {"backend":{"status":"Healthy","index_count":N},...}

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/health")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if has(r.body, "marqo") or (has(r.body, '"backend"') and has(r.body, "index_count")) then
    return { service = "Marqo", path = "/health",
             auth = auth_of(r), cors = cors_open(r) }
  end
end

-- FauxPilot
-- GitHub Copilot-compatible inference; uses /v1/engines (Codex namespace, not /v1/models)

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/v1/engines")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if has(r.body, '"data"') and (has(r.body, "engine") or has(r.body, "fauxpilot")
  or has(r.body, "copilot") or has(r.body, "codex")) then
    return { service = "FauxPilot", path = "/v1/engines",
             auth = auth_of(r), cors = cors_open(r) }
  end
end

-- Jan
-- /api/assistants exposes Jan-specific fields (avatar, instructions); distinct
-- from the OpenAI-compat fingerprint in /v1/models

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/api/assistants")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if has(r.body, '"avatar"') or has(r.body, '"instructions"')
  or has(r.body, "jan") or has(hdr(r, "server"), "jan") then
    return { service = "Jan", path = "/api/assistants",
             auth = auth_of(r), cors = cors_open(r) }
  end
end

-- FastAPI / OpenAPI catch-all
-- /openapi.json: requires AI keywords in title or paths to avoid generic hits.
-- /docs: Swagger UI left accessible means the full API spec is browseable.

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/openapi.json")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if not has(r.body, '"openapi"') then return nil end
  local body = r.body or ""
  local title = jstr(body, "title") or ""
  local ai_title = has(title, "llm") or has(title, "embed") or has(title, "inference")
               or has(title, "completion") or has(title, "chat") or has(title, "model")
               or has(title, "ai") or has(title, "gpt")
  local ai_path = has(body, '"/v1/') or has(body, '"/generate"') or has(body, '"/embed"')
               or has(body, '"/completions"') or has(body, '"/chat/completions"')
  if not ai_title and not ai_path then return nil end
  -- Check if Swagger UI docs are also exposed (additional exposure signal)
  local docs = cget("/docs")
  local note = title ~= "" and ("title: " .. title) or nil
  if docs and docs.status == 200 and has(docs.body, "swagger") then
    note = (note and note .. "; " or "") .. "Swagger UI exposed at /docs"
  end
  return { service = "AI API (FastAPI/OpenAPI)", path = "/openapi.json",
           auth = auth_of(r), cors = cors_open(r), note = note }
end

-- Model file directory listing
-- Checks /, /models, /weights, /checkpoints for directory listings with model
-- file extensions. GGUF/SafeTensors/ONNX are unambiguous; .pt/.bin only flagged
-- when found alongside at least one of those.

PROBES[#PROBES+1] = function(cget, _)
  local model_dirs = { "/", "/models", "/weights", "/checkpoints" }
  local seen_ext   = {}
  local found_exts = {}
  local hit_paths  = {}

  for _, dir in ipairs(model_dirs) do
    local r = cget(dir)
    if r and r.status == 200 then
      local body = (r.body or ""):lower()
      if body:find("<a%s", 1) then
        local dir_hit = false
        for _, pair in ipairs({
          {"%.gguf",        "GGUF"},
          {"%.safetensors", "SafeTensors"},
          {"%.onnx",        "ONNX"},
        }) do
          if body:find(pair[1], 1) and not seen_ext[pair[2]] then
            seen_ext[pair[2]] = true
            found_exts[#found_exts+1] = pair[2]
            dir_hit = true
          end
        end
        if dir_hit then hit_paths[#hit_paths+1] = dir end
      end
    end
  end

  if #found_exts == 0 then return nil end

  -- .pt and .bin only flagged alongside unambiguous model exts
  for _, dir in ipairs(hit_paths) do
    local r = cget(dir)
    local body = r and (r.body or ""):lower() or ""
    if body:find('%.pt"',  1, true) or body:find("%.pt<",  1, true) then
      if not seen_ext["PT"]  then seen_ext["PT"]  = true; found_exts[#found_exts+1] = "PT"  end
    end
    if body:find('%.bin"', 1, true) or body:find("%.bin<", 1, true) then
      if not seen_ext["BIN"] then seen_ext["BIN"] = true; found_exts[#found_exts+1] = "BIN" end
    end
  end

  table.sort(found_exts)
  local first = cget(hit_paths[1])
  return { service = "Model File Server",
           path    = table.concat(hit_paths, ", "),
           auth    = first and auth_of(first) or nil,
           cors    = first and cors_open(first) or false,
           note    = "model files exposed: " .. table.concat(found_exts, ", ") }
end

-- ChromaDB

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/api/v1/heartbeat")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if not has(r.body, "heartbeat") then return nil end
  local vr = cget("/api/v1/version")  -- cached if already fetched
  return { service = "ChromaDB", path = "/api/v1/heartbeat",
           auth = auth_of(r), cors = cors_open(r),
           version = vr and jstr(vr.body, "version") or nil }
end

-- Qdrant

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/")  -- cached; free if already fetched by MCP probe
  if r and r.status == 200 and has(hdr(r, "server"), "qdrant") then
    return { service = "Qdrant", path = "/",
             auth = auth_of(r), cors = cors_open(r),
             version = jstr(r.body, "version") }
  end
  r = cget("/collections")
  if r and r.status == 200 and not is_html(r)
  and has(r.body, '"collections"') and has(r.body, '"status"') and has(r.body, '"time"') then
    return { service = "Qdrant", path = "/collections",
             auth = auth_of(r), cors = cors_open(r) }
  end
end

-- Weaviate

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/v1/meta")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if has(r.body, "weaviate") or has(hdr(r, "server"), "weaviate") then
    return { service = "Weaviate", path = "/v1/meta",
             auth = auth_of(r), cors = cors_open(r),
             version = jstr(r.body, "version") }
  end
end

-- Milvus

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/healthz")  -- cached; shared with n8n probe
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if not has(r.body, '"data"') or not has(r.body, '"code"') then return nil end
  local cr = cget("/v1/vector/collections")
  if cr and (cr.status == 200 or cr.status == 401) then
    return { service = "Milvus", path = "/healthz",
             auth = auth_of(r), cors = cors_open(r) }
  end
end

-- MLflow

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/api/2.0/mlflow/experiments/list")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if has(r.body, "experiments") then
    return { service = "MLflow", path = "/api/2.0/mlflow/experiments/list",
             auth = auth_of(r), cors = cors_open(r) }
  end
end

-- Jupyter

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/api/status")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if has(r.body, "last_activity") and has(r.body, "started") then
    return { service = "Jupyter", path = "/api/status",
             auth = auth_of(r), cors = cors_open(r) }
  end
end

-- TensorBoard

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/api/experiments")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if has(r.body, "tensorflow") or has(r.body, "tensorboard")
  or has(hdr(r, "server"), "tensorboard") then
    return { service = "TensorBoard", path = "/api/experiments",
             auth = auth_of(r), cors = cors_open(r) }
  end
end

-- Ray Dashboard

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/api/cluster_status")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if has(r.body, "rayVersion") and has(r.body, "nodes") then
    return { service = "Ray Dashboard", path = "/api/cluster_status",
             auth = auth_of(r), cors = cors_open(r),
             version = jstr(r.body, "rayVersion") }
  end
end

-- Ray Serve
-- /api/serve/applications/ runs on the same port as the Ray Dashboard above.
-- Trailing slash is required — without it the endpoint 404s (confirmed
-- against a real Ray 2.57.0 instance; not documented anywhere obviously).
-- "proxies" (per-node ingress routing info) is Serve-specific — the generic
-- cluster_status probe above has no such field, so this only fires when
-- Serve is actually deployed on the cluster, not just the dashboard.

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/api/serve/applications/")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if not has(r.body, '"applications"') or not has(r.body, '"proxies"') then return nil end
  return { service = "Ray Serve", path = "/api/serve/applications/",
           auth = auth_of(r), cors = cors_open(r) }
end

-- n8n

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/healthz")  -- cached; shared with Milvus probe
  if r and r.status == 200 and not is_html(r) and (has(r.body, "n8n") or has(hdr(r, "server"), "n8n")) then
    return { service = "n8n", path = "/healthz",
             auth = auth_of(r), cors = cors_open(r) }
  end
  r = cget("/rest/active-workflows")
  if r and (r.status == 200 or r.status == 401) and not is_html(r)
  and (has(r.body, "workflow") or has(hdr(r, "server"), "n8n")) then
    return { service = "n8n", path = "/rest/active-workflows",
             auth = auth_of(r) }
  end
end

-- NVIDIA DCGM Exporter
-- /metrics is cached — no extra request if vLLM or generic probe already fetched it

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/metrics")
  if not r or r.status ~= 200 then return nil end
  if has(r.body, "DCGM_") then
    return { service = "NVIDIA DCGM Exporter", path = "/metrics",
             note = "GPU telemetry exposed — inference host likely" }
  end
end

-- Generic AI Prometheus metrics
-- /metrics is cached — third probe to use it, zero extra requests

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/metrics")
  if not r or r.status ~= 200 then return nil end
  -- Skip if already matched by more specific probes
  if has(r.body, "vllm:") or has(r.body, "vllm_") or has(r.body, "DCGM_") then return nil end
  local signals = {}
  if has(r.body, "nvidia_gpu_")      then signals[#signals+1] = "nvidia_gpu"      end
  if has(r.body, "model_inference_") then signals[#signals+1] = "model_inference" end
  if has(r.body, "triton_")          then signals[#signals+1] = "triton"          end
  if has(r.body, "torchserve_")      then signals[#signals+1] = "torchserve"      end
  if has(r.body, "aphrodite_")       then signals[#signals+1] = "aphrodite"       end
  if has(r.body, "llamacpp_")        then signals[#signals+1] = "llamacpp"        end
  if has(r.body, "sglang_")          then signals[#signals+1] = "sglang"          end
  if has(r.body, "xinference_")      then signals[#signals+1] = "xinference"      end
  if #signals == 0 then return nil end
  return { service = "AI metrics (Prometheus)", path = "/metrics",
           note = "metrics: " .. table.concat(signals, ", ") }
end

-- MCP: header + body detection
-- Uses cached /; free if Qdrant probe already fetched root.
-- Body string detection is skipped on text/html responses — web UIs (MCPoke,
-- docs pages, etc.) contain MCP method names in their JavaScript but are not
-- MCP endpoints. Only JSON and SSE responses carry actual protocol payloads.

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/")
  if not r then return nil end

  if hdr(r, "mcp-session-id") ~= "" then
    return { service = "MCP Server", path = "/",
             auth = auth_of(r), note = "Mcp-Session-Id header present" }
  end

  local ct = hdr(r, "content-type")
  if has(ct, "text/html") then return nil end  -- skip web UI pages

  local body = r.body or ""
  local has_proto = has(body, "protocolVersion") and
    (has(body, "2024-11-05") or has(body, "2025-03-26") or has(body, "2025-11-25"))

  if has(body, "modelcontextprotocol") or has(body, "@modelcontextprotocol/sdk")
  or has_proto or (has(body, "tools/list") and has(body, "tools/call")) then
    return { service = "MCP Server", path = "/",
             auth = auth_of(r), note = "MCP strings in body" }
  end
end

-- MCP: .well-known/mcp discovery

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/.well-known/mcp")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if has(r.body, "mcp") or has(r.body, "modelcontextprotocol") then
    return { service = "MCP Server", path = "/.well-known/mcp",
             auth = auth_of(r), note = "discovery endpoint present" }
  end
end

-- MCP: SSE transport

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/sse")
  if not r then return nil end
  if has(hdr(r, "content-type"), "text/event-stream") then
    return { service = "MCP Server (SSE)", path = "/sse",
             auth = auth_of(r), note = "SSE stream accepted" }
  end
end

-- MCP: JSON-RPC initialize (active POST)
-- Tries 2025-11-25 first, then 2025-03-26, then 2024-11-05 on JSON-RPC error.

PROBES[#PROBES+1] = function(_, cpost)
  if NO_POST then return nil end

  local _MCP_INIT_LATEST = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":' ..
    '{"protocolVersion":"2025-11-25","capabilities":{},' ..
    '"clientInfo":{"name":"nmap-http-ai-enum","version":"1.0"}}}'
  local _MCP_INIT_2025 = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":' ..
    '{"protocolVersion":"2025-03-26","capabilities":{},' ..
    '"clientInfo":{"name":"nmap-http-ai-enum","version":"1.0"}}}'
  local _MCP_INIT_2024 = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":' ..
    '{"protocolVersion":"2024-11-05","capabilities":{},' ..
    '"clientInfo":{"name":"nmap-http-ai-enum","version":"1.0"}}}'

  local function try_init(path, init_body)
    local r = cpost(path, init_body)
    if not r or r.status ~= 200 then return nil end
    if has(hdr(r, "content-type"), "text/html") then return nil end
    if not has(r.body, "protocolVersion") or not has(r.body, "jsonrpc") then return nil end
    if has(r.body, '"error"') and not has(r.body, '"result"') then return nil end
    return r
  end

  for _, path in ipairs({ "/", "/mcp", "/rpc", "/v1", "/sse" }) do
    local r = try_init(path, _MCP_INIT_LATEST) or try_init(path, _MCP_INIT_2025) or try_init(path, _MCP_INIT_2024)
    if r then
      local proto = jstr(r.body, "protocolVersion")
      local sname = jstr(r.body, "name")
      local caps = {}
      local caps_block = (r.body or ""):match('"capabilities"%s*:%s*(%b{})')
      if caps_block then
        for cap in caps_block:gmatch('"([a-zA-Z][a-zA-Z0-9_]*)"%s*:') do
          caps[#caps+1] = cap
        end
      end
      local note = sname and ("server: " .. sname) or "responded to initialize"
      if #caps > 0 then note = note .. "  capabilities: " .. table.concat(caps, ",") end
      return { service = "MCP Server", path = path,
               auth = auth_of(r), version = proto, note = note }
    end
  end
end

-- Langfuse (self-hosted LLM observability)
-- /api/public/health is Langfuse-specific: returns {"version":"x.y.z","status":"ok"}.
-- Secondary check: /api/public/traces must return 200 or 401 (non-HTML) — any
-- server that has both endpoints is almost certainly Langfuse.

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/api/public/health")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if not has(r.body, '"status"') or not has(r.body, '"version"') then return nil end
  if not (has(r.body, "langfuse") or has(hdr(r, "x-powered-by"), "langfuse")
      or has(hdr(r, "server"), "langfuse")) then
    local tr = cget("/api/public/traces")
    if not tr or is_html(tr) or (tr.status ~= 200 and tr.status ~= 401) then return nil end
  end
  return { service = "Langfuse", path = "/api/public/health",
           auth = auth_of(r), cors = cors_open(r),
           version = jstr(r.body, "version") }
end

-- Arize Phoenix (LLM observability)
-- Root HTML contains both "arize" and "phoenix" when Phoenix is running.
-- Disambiguate from other services named "Phoenix" by requiring both strings.

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/")
  if not r or r.status ~= 200 then return nil end
  if has(hdr(r, "content-type"), "text/html")
  and has(r.body, "arize") and has(r.body, "phoenix") then
    return { service = "Arize Phoenix", path = "/",
             auth = auth_of(r), cors = cors_open(r) }
  end
  -- Some deployments expose /v1/projects (Phoenix REST API)
  local pr = cget("/v1/projects")
  if pr and pr.status == 200 and not is_html(pr)
  and has(pr.body, '"data"') and has(pr.body, "phoenix") then
    return { service = "Arize Phoenix", path = "/v1/projects",
             auth = auth_of(pr), cors = cors_open(pr) }
  end
end

-- Unstructured API (document partitioning for RAG pipelines)
-- /healthcheck key name is Unstructured-specific (not "status", "ok", or "healthy").
-- /general/v0/general is the partition endpoint; GET returns 405.

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/healthcheck")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if not has(r.body, '"healthcheck"') then return nil end
  local gr = cget("/general/v0/general")
  if not gr or (gr.status ~= 200 and gr.status ~= 405 and gr.status ~= 422) then return nil end
  return { service = "Unstructured API", path = "/healthcheck",
           auth = auth_of(r), cors = cors_open(r) }
end

-- Whisper / Speech-to-Text API servers
-- faster-whisper-server exposes /asr; OpenAI-compat STT servers list
-- audio/transcription paths in /openapi.json with whisper/asr keywords in the title.

PROBES[#PROBES+1] = function(cget, _)
  local asr = cget("/asr")
  if asr and asr.status == 200 and not is_html(asr)
  and (has(asr.body, "audio") or has(asr.body, "transcri")) then
    return { service = "Whisper STT Server", path = "/asr",
             auth = auth_of(asr), cors = cors_open(asr) }
  end
  local r = cget("/openapi.json")
  if not r or r.status ~= 200 or is_html(r) or not has(r.body, '"openapi"') then return nil end
  local title = (jstr(r.body, "title") or ""):lower()
  local body  = (r.body or ""):lower()
  if (has(title, "whisper") or has(title, "asr") or has(title, "transcri") or has(title, "speech"))
  and (has(body, "/audio") or has(body, "transcri") or has(body, '"asr"')) then
    return { service = "Whisper STT Server", path = "/openapi.json",
             auth = auth_of(r), cors = cors_open(r),
             note = "title: " .. (jstr(r.body, "title") or "") }
  end
end

-- Coqui TTS server
-- /api/speakers returns an array with language_ids / display_name — unique to Coqui.

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/api/speakers")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if has(r.body, '"language_ids"') or has(r.body, '"display_name"')
  or has(r.body, '"style_wav"') then
    return { service = "Coqui TTS", path = "/api/speakers",
             auth = auth_of(r), cors = cors_open(r) }
  end
end

-- Chainlit (chat app framework / UI)
-- Serves an SPA at / with Chainlit-specific JavaScript markers in the HTML.

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/")
  if not r or r.status ~= 200 then return nil end
  if not has(hdr(r, "content-type"), "text/html") then return nil end
  if has(r.body, "chainlit") or has(r.body, "__chainlit__")
  or has(r.body, "/_chainlit/") then
    return { service = "Chainlit", path = "/",
             auth = auth_of(r), cors = cors_open(r) }
  end
end

-- Typesense (vector-capable search engine)
-- /health → {"ok":true} is short and clean; /collections without API key
-- returns a distinctive error mentioning x-typesense-api-key.

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/health")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if not has(r.body, '"ok"') or #(r.body or "") > 50 then return nil end
  local cr = cget("/collections")
  if not cr then return nil end
  if cr.status == 200 or has(cr.body, "typesense") or has(cr.body, "x-typesense-api-key") then
    local auth_state = cr.status == 200 and "UNAUTHENTICATED" or auth_of(cr)
    return { service = "Typesense", path = "/health",
             auth = auth_state, cors = cors_open(r) }
  end
end

-- AllTalk TTS (text-to-speech server)
-- /api/alltalk_settings is unique to AllTalk — no other TTS server uses this path.

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/api/alltalk_settings")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if not has(r.body, '"') then return nil end
  return { service = "AllTalk TTS", path = "/api/alltalk_settings",
           auth = auth_of(r), cors = cors_open(r) }
end

-- ClearML (ML experiment tracking / MLOps)
-- Versioned debug.ping path is ClearML-specific; tries current and recent API versions.
-- Response wraps data in a {"data":{...}} envelope — ClearML's standard API shape.

PROBES[#PROBES+1] = function(cget, _)
  for _, path in ipairs({ "/api/v2.3/debug.ping", "/api/v2.4/debug.ping",
                          "/api/v2.5/debug.ping", "/api/v2.6/debug.ping" }) do
    local r = cget(path)
    if r and r.status == 200 and not is_html(r)
    and (has(r.body, '"data"') or has(r.body, "clearml") or has(r.body, "trains")) then
      return { service = "ClearML", path = path,
               auth = auth_of(r), cors = cors_open(r) }
    end
  end
end

-- Determined AI (distributed ML training platform)
-- /api/v1/master is not a Kubernetes endpoint; returns cluster info with
-- master_version and cluster_id fields that are Determined-specific.

PROBES[#PROBES+1] = function(cget, _)
  local r = cget("/api/v1/master")
  if not r or r.status ~= 200 or is_html(r) then return nil end
  if not has(r.body, "master_version") and not has(r.body, "cluster_id") then return nil end
  return { service = "Determined AI", path = "/api/v1/master",
           auth = auth_of(r), cors = cors_open(r),
           version = jstr(r.body, "version") }
end

-- Result merging
-- Collapses multiple probe hits for the same service into one entry:
-- union of models, all matched paths, most-open auth, any CORS flag.

local function merge_findings(raw)
  local merged = {}
  local order  = {}

  for _, f in ipairs(raw) do
    local svc = f.service
    if not merged[svc] then
      merged[svc] = { service = svc, paths = {}, models = {}, seen_m = {},
                      version = nil, auth = nil, cors = false, notes = {} }
      order[#order+1] = svc
    end
    local e = merged[svc]

    e.paths[#e.paths+1] = f.path

    for _, m in ipairs(f.models or {}) do
      if not e.seen_m[m] then e.seen_m[m] = true; e.models[#e.models+1] = m end
    end

    if f.version and not e.version then e.version = f.version end

    -- Escalate to most-permissive auth state seen
    if f.auth == "UNAUTHENTICATED" then
      e.auth = "UNAUTHENTICATED"
    elseif f.auth and not e.auth then
      e.auth = f.auth
    end

    if f.cors then e.cors = true end

    if f.note then
      local dup = false
      for _, n in ipairs(e.notes) do if n == f.note then dup = true; break end end
      if not dup then e.notes[#e.notes+1] = f.note end
    end
  end

  local out = {}
  for _, svc in ipairs(order) do out[#out+1] = merged[svc] end
  return out
end

-- Action

action = function(host, port)
  local get_opts = {
    timeout = TIMEOUT,
    header  = { ["Accept"]     = "application/json, text/event-stream, */*",
                ["User-Agent"] = "Mozilla/5.0" },
  }
  local post_opts = {
    timeout = TIMEOUT,
    header  = { ["Content-Type"] = "application/json",
                ["Accept"]       = "application/json" },
  }

  local cache = {}
  local function cget(path)
    if cache[path] == nil then
      local ok, r = pcall(http.get, host, port, path, get_opts)
      cache[path] = (ok and r and r.status) and r or false
    end
    return cache[path] ~= false and cache[path] or nil
  end

  local function cpost(path, body)
    local ok, r = pcall(http.post, host, port, path, post_opts, nil, body)
    return (ok and r and r.status) and r or nil
  end

  local raw = {}
  for _, probe in ipairs(PROBES) do
    local ok, result = pcall(probe, cget, cpost)
    if ok and result and result.service then
      raw[#raw+1] = result
    end
  end

  if #raw == 0 then return nil end

  local findings = merge_findings(raw)
  local output   = stdnse.output_table()

  -- Set port.version.product for confident single-service identifications so
  -- the service name appears in the main nmap port table, not just script output.
  -- Generic catch-all service names that shouldn't override nmap's version product.
  -- Everything else is specific enough to be worth surfacing in the port table.
  local _GENERIC = {
    ["OpenAI-compatible API"]    = true,
    ["AI API (FastAPI/OpenAPI)"] = true,
    ["AI metrics (Prometheus)"]  = true,
    ["Model File Server"]        = true,
  }
  if #findings >= 1 and not _GENERIC[findings[1].service] then
    local f = findings[1]
    port.version.name    = "http"
    port.version.product = f.service
    if f.version then port.version.version = f.version end
    nmap.set_port_version(host, port, "softmatched")
  end

  -- Stash confirmed MCP endpoint in the registry for http-mcp-enum.nse to reuse.
  for _, f in ipairs(findings) do
    if f.service:find("MCP", 1, true) then
      nmap.registry[host.ip] = nmap.registry[host.ip] or {}
      nmap.registry[host.ip][port.number] = nmap.registry[host.ip][port.number] or {}
      nmap.registry[host.ip][port.number]["http_ai_enum_mcp"] = f.paths[1]
      break
    end
  end

  for _, f in ipairs(findings) do
    local entry = stdnse.output_table()

    entry["path"] = table.concat(f.paths, ", ")

    local sec = f.auth or "unknown"
    if f.cors then sec = sec .. "  CORS:*" end
    entry["security"] = sec

    if f.version then entry["version"] = f.version end

    if #f.models > 0 then
      local shown = math.min(#f.models, MAX_MODELS)
      local mlist = table.concat(f.models, ", ", 1, shown)
      if #f.models > shown then
        mlist = mlist .. " (+" .. (#f.models - shown) .. " more)"
      end
      entry["models"] = mlist
    end

    if #f.notes > 0 then entry["note"] = table.concat(f.notes, "; ") end

    output[f.service] = entry
  end

  return output
end
