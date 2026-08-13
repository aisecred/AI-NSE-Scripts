local http      = require "http"
local nmap      = require "nmap"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local string    = require "string"
local table     = require "table"

description = [[
Actively probes Model Context Protocol (MCP) servers to enumerate tools,
resources, resource templates, and prompts via multiple transport methods.

Transport methods tried in order:
  1. .well-known/mcp  — spec-defined discovery; gives canonical path and transport type
  2. Streamable HTTP  — POST to /mcp, /, /rpc, /api, /v1
                         2026-07-28 stateless protocol tried first, then legacy stateful
  3. SSE (legacy)     — GET /sse, /events, /stream, /v1/sse, /api/sse, /mcp/sse, etc.
                         handles both response styles: synchronous (JSON-RPC
                         reply in the POST response) and async-push (POST
                         returns a bare 202; the reply is a later event on
                         the original SSE stream)

On each candidate endpoint, first tries the 2026-07-28 stateless protocol — no
initialize/session, per-request _meta carrying protocol version and client
capabilities instead. Falls back to the legacy stateful JSON-RPC handshake:
  initialize (2025-11-25, falling back to 2025-03-26 then 2024-11-05)
  → notifications/initialized
Both paths then enumerate:
  tools/list (paginated) + inputSchema required-param extraction +
              annotations (readOnlyHint/destructiveHint/idempotentHint/openWorldHint)
  → resources/list (paginated, static URIs + URI templates)
  → prompts/list (paginated) + prompts/get for each prompt

Security signals surfaced automatically:
  auth:         UNAUTHENTICATED / 401 scheme / 403, plus OAuth protected-resource
                metadata (RFC 9728) when a 401 advertises or implies one
  CORS:*        Access-Control-Allow-Origin: * on the MCP endpoint
  WARNING:      server sent an unsolicited sampling/createMessage request — a protocol
                violation, since we never declare client-side sampling support
  needs further input: a tool call, resource read, or prompt fetch was interrupted by
                a server-initiated request (e.g. elicitation/create) we didn't fulfill
  annotations:  per-tool DESTRUCTIVE/read-only/non-destructive tag; a tool declaring no
                annotations at all is tagged distinctly, since the spec's own defaults
                lean toward "assume destructive" and most real tools omit them entirely
  capability notes: resources.subscribe — push notifications on resource changes

With http-mcp-enum.call=1, each tool is called using its required parameters as keys
with empty string values.  This gets further into tool logic than a bare {} call and
often produces error messages that reveal path structures, DB schemas, or file layout.

With http-mcp-enum.read=1, the first three discovered resources are read via
resources/read and a content preview is shown.

Script arguments:
  http-mcp-enum.timeout=N         Per-request HTTP timeout in milliseconds (default 6000).
  http-mcp-enum.call=1            Call each tool with schema-derived arguments and report responses.
  http-mcp-enum.read=1            Read the first three resources and show a content preview.
  http-mcp-enum.max_tools=N       Maximum number of tools to display per server (default: unlimited).
  http-mcp-enum.max_pages=N       Maximum list pagination pages to follow per method (default 5).
  http-mcp-enum.token=VALUE       Bearer token — sends Authorization: Bearer VALUE on all requests.
  http-mcp-enum.header=NAME:VALUE Arbitrary header for API key schemes (e.g. X-Api-Key:secret).
  http-mcp-enum.basic=USER:PASS   HTTP Basic auth — base64-encodes USER:PASS automatically.

Usage:
  # Common MCP ports
  nmap -sV -p 3000,3001,8000,8080,8443,9000,9001 --script http-mcp-enum <target>

  # Full sweep
  nmap -sV -p- --script http-mcp-enum <target>

  # Active probing — call tools and read resources
  nmap -sV --script http-mcp-enum --script-args http-mcp-enum.call=1,http-mcp-enum.read=1 <target>
]]

author       = "find_all_ai"
license      = "Same as Nmap -- https://nmap.org/book/man-legal.html"
categories   = {"discovery", "safe"}
dependencies = {"http-ai-enum"}

-- Port rule

local _EXTRA = {
  1234, 3000, 3001, 4000, 5000, 5001, 7860, 8000, 8081, 8443,
  8888, 9000, 9001, 9090, 11434,
}

portrule = function(host, port)
  if port.protocol ~= "tcp" or port.state ~= "open" then return false end
  if shortport.http(host, port) then return true end
  local sfp = (port.version and port.version.service_fp or "")
  if sfp:find("HTTP/1", 1, true) or sfp:find("HTTP/2", 1, true) then return true end
  for _, p in ipairs(_EXTRA) do
    if port.number == p then return true end
  end
  return false
end

-- Script args

local TIMEOUT   = tonumber(stdnse.get_script_args("http-mcp-enum.timeout"))   or 6000
local DO_CALL   = stdnse.get_script_args("http-mcp-enum.call")
local DO_READ   = stdnse.get_script_args("http-mcp-enum.read")
local MAX_TOOLS = tonumber(stdnse.get_script_args("http-mcp-enum.max_tools")) or 1000
local MAX_PAGES = tonumber(stdnse.get_script_args("http-mcp-enum.max_pages")) or 5

local AUTH_HEADER, AUTH_VALUE
do
  local token  = stdnse.get_script_args("http-mcp-enum.token")
  local hdr_arg = stdnse.get_script_args("http-mcp-enum.header")
  local basic  = stdnse.get_script_args("http-mcp-enum.basic")
  if token then
    AUTH_HEADER = "Authorization"
    AUTH_VALUE  = "Bearer " .. token
  elseif hdr_arg then
    local sep = hdr_arg:find(":", 1, true)
    if sep then
      AUTH_HEADER = hdr_arg:sub(1, sep - 1)
      AUTH_VALUE  = hdr_arg:sub(sep + 1)
    end
  elseif basic then
    AUTH_HEADER = "Authorization"
    AUTH_VALUE  = "Basic " .. (require "base64").enc(basic)
  end
end

-- JSON-RPC constants

local INIT_LATEST = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":' ..
  '{"protocolVersion":"2025-11-25","capabilities":{},' ..
  '"clientInfo":{"name":"nmap-http-mcp-enum","version":"1.0"}}}'

local INIT_2025 = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":' ..
  '{"protocolVersion":"2025-03-26","capabilities":{},' ..
  '"clientInfo":{"name":"nmap-http-mcp-enum","version":"1.0"}}}'

local INIT_2024 = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":' ..
  '{"protocolVersion":"2024-11-05","capabilities":{},' ..
  '"clientInfo":{"name":"nmap-http-mcp-enum","version":"1.0"}}}'

local INIT_NOTIF = '{"jsonrpc":"2.0","method":"notifications/initialized"}'

-- 2026-07-28 stateless protocol: no initialize/session — every request carries
-- protocol version and client capabilities in params._meta instead.
local STATELESS_VERSION = "2026-07-28"
local STATELESS_META = '"_meta":{"io.modelcontextprotocol/protocolVersion":"' .. STATELESS_VERSION .. '",' ..
  '"io.modelcontextprotocol/clientCapabilities":{},' ..
  '"io.modelcontextprotocol/clientInfo":{"name":"nmap-http-mcp-enum","version":"1.0"}}'

-- Pure helpers

local function has(s, pat)
  if not s or s == "" then return false end
  return s:lower():find(pat:lower(), 1, true) ~= nil
end

-- Fast extraction for short, well-behaved JSON string values (names, versions).
local function jstr(body, key)
  if not body then return nil end
  return body:match('"' .. key .. '"%s*:%s*"([^"]*)"')
end

-- Full extraction that handles \" escapes — for content fields that may contain
-- embedded JSON, quotes, or special characters. Returns up to 400 chars raw.
local function jstr_raw(body, key)
  if not body then return nil end
  local s, e = body:find('"' .. key .. '"%s*:%s*"')
  if not s then return nil end
  local i = e + 1
  local chars = {}
  while i <= #body and #chars < 400 do
    local c = body:sub(i, i)
    if c == '"' then break
    elseif c == '\\' and i < #body then
      local esc = body:sub(i + 1, i + 1)
      if     esc == 'n'  then chars[#chars+1] = ' '
      elseif esc == 't'  then chars[#chars+1] = ' '
      elseif esc == '"'  then chars[#chars+1] = '"'
      elseif esc == '\\' then chars[#chars+1] = '\\'
      end
      i = i + 2
    else
      chars[#chars+1] = c
      i = i + 1
    end
  end
  local v = table.concat(chars)
  return v ~= "" and v or nil
end

-- Trim s to limit chars, appending "..." when truncated.
local function trim(s, limit)
  if not s then return nil end
  if #s <= limit then return s end
  return s:sub(1, limit - 3) .. "..."
end

local function hdr(r, name)
  if not r or not r.header then return "" end
  return r.header[name:lower()] or ""
end

-- Strip SSE framing. %b{} captures exactly the first balanced JSON object,
-- preventing greedy match from spanning multiple SSE events.
local function unwrap_sse(body)
  if not body or body == "" then return body end
  if not body:find("^data:", 1, true) then return body end
  return body:match("data:%s*(%b{})") or body
end

local function next_cursor(body)
  if not body then return nil end
  local c = body:match('"nextCursor"%s*:%s*"([^"]*)"')
  return (c and c ~= "") and c or nil
end

local SAMPLING_WARNING = "WARNING: server sent an unsolicited sampling/createMessage " ..
  "request — client never declared sampling support, so this is a protocol violation"

-- Detects an unrequested sampling/createMessage attempt in a server response —
-- the server trying to invoke an LLM completion through us despite our
-- initialize/bootstrap never declaring client-side sampling support. Per spec
-- a compliant server MUST NOT do this unless the client declared support, so
-- seeing it here is itself the signal, regardless of which wire shape it uses:
--   legacy:      a bare server-initiated JSON-RPC request (has "method", no
--                "result"/"error")
--   2026-07-28:  an InputRequiredResult naming it in inputRequests
local function sampling_attempt(body)
  if not body then return false end
  if has(body, '"method"') and has(body, '"sampling/createMessage"')
  and not has(body, '"result"') and not has(body, '"error"') then
    return true
  end
  if has(body, '"resultType"') and has(body, '"input_required"')
  and has(body, '"sampling/createMessage"') then
    return true
  end
  return false
end

-- Detects a server-initiated request that needs a follow-up from us to
-- complete the original call — e.g. elicitation/create or roots/list under
-- MRTR (2026-07-28), or the pre-MRTR direct server-initiated pattern (same
-- shape sampling_attempt checks, but for methods other than sampling, which
-- gets its own WARNING above and isn't re-reported here). We don't attempt
-- the round-trip; this just reports what was asked for instead of silently
-- dropping it, which the plain result/error checks below would otherwise do.
local function pending_request(body)
  if not body then return nil end
  local m = body:match('"method"%s*:%s*"([%w_%./%-]+)"')
  if m and m ~= "sampling/createMessage"
  and not has(body, '"result"') and not has(body, '"error"') then
    return m
  end
  return nil
end

-- JSON parsers

-- Resolves a tool's "annotations" block (readOnlyHint/destructiveHint/
-- idempotentHint/openWorldHint) into a short tag. The spec's defaults lean
-- toward "assume risk" (readOnlyHint defaults false, destructiveHint
-- defaults true), but most real tools declare no annotations at all
-- (confirmed against the mcp_test_servers lab) -- applying the destructive
-- default blindly would tag every single one "DESTRUCTIVE" and the signal
-- would drown in noise. So destructiveHint specifically tracks whether it
-- was actually declared, and an undeclared tool is tagged distinctly from
-- one explicitly marked destructive. destructiveHint/idempotentHint are
-- only meaningful when readOnlyHint is false, per spec.
local function tool_annotation_tag(obj)
  local block = obj:match('"annotations"%s*:%s*(%b{})')
  local function bool_field(name, default)
    if block then
      if block:find('"' .. name .. '"%s*:%s*true')  then return true,  true end
      if block:find('"' .. name .. '"%s*:%s*false') then return false, true end
    end
    return default, false
  end
  local read_only  = (bool_field("readOnlyHint", false))
  local open_world = (bool_field("openWorldHint", true))
  if read_only then
    return "read-only" .. (open_world == false and ", closed-world" or "")
  end
  local destructive, destructive_declared = bool_field("destructiveHint", true)
  local idempotent = (bool_field("idempotentHint", false))
  local tag
  if not destructive_declared then
    tag = "unannotated (spec default: assume destructive)"
  elseif destructive then
    tag = "DESTRUCTIVE"
  else
    tag = "non-destructive"
  end
  if destructive_declared and idempotent then tag = tag .. ", idempotent" end
  if open_world == false then tag = tag .. ", closed-world" end
  return tag
end

-- Tools: [{name, description, required=[], annotations}]
-- Uses a string-aware walker instead of %b[] — Lua's %b[] counts every [ and ]
-- including those inside JSON string values, so a description like "filter by
-- status=active]" would terminate the array match prematurely and silently
-- return zero tools.
local function parse_tools(body)
  if not body then return {} end
  local key_pos = body:find('"tools"%s*:%s*%[')
  if not key_pos then return {} end
  local arr_open = body:find('%[', key_pos)
  if not arr_open then return {} end

  local out = {}
  local i, depth, in_str, esc, obj_s = arr_open + 1, 0, false, false, nil
  while i <= #body do
    local c = body:sub(i, i)
    if esc then
      esc = false
    elseif in_str then
      if c == '\\' then esc = true elseif c == '"' then in_str = false end
    else
      if     c == '"' then in_str = true
      elseif c == '{' then depth = depth + 1; if depth == 1 then obj_s = i end
      elseif c == '}' then
        depth = depth - 1
        if depth == 0 and obj_s then
          local obj = body:sub(obj_s, i)
          local name = obj:match('"name"%s*:%s*"([^"]+)"')
          if name then
            local desc = trim(jstr_raw(obj, "description") or "", 400)
            local required = {}
            local req_arr = obj:match('"required"%s*:%s*(%b[])')
            if req_arr then
              for param in req_arr:gmatch('"([^"]+)"') do
                required[#required+1] = param
              end
            end
            out[#out+1] = { name = name, description = desc, required = required,
                            annotations = tool_annotation_tag(obj) }
          end
          obj_s = nil
        end
      elseif c == ']' and depth == 0 then
        break
      end
    end
    i = i + 1
  end
  return out
end

-- Static resources: [{name, uri}]
local function parse_resources(body)
  if not body then return {} end
  local arr = body:match('"resources"%s*:%s*(%b[])')
  if not arr then return {} end
  local out = {}
  for obj in arr:gmatch('%b{}') do
    local uri  = obj:match('"uri"%s*:%s*"([^"]*)"')
    local name = obj:match('"name"%s*:%s*"([^"]*)"') or ""
    if uri and uri ~= "" then
      out[#out+1] = { name = name, uri = uri }
    end
  end
  return out
end

-- Resource templates (MCP 2025-03-26): [{name, uri_template, description}]
-- Templates have RFC 6570 URI patterns like file:///{path} or db://{table}/{id}.
local function parse_resource_templates(body)
  if not body then return {} end
  local arr = body:match('"resourceTemplates"%s*:%s*(%b[])')
  if not arr then return {} end
  local out = {}
  for obj in arr:gmatch('%b{}') do
    local tmpl = obj:match('"uriTemplate"%s*:%s*"([^"]*)"')
    local name = obj:match('"name"%s*:%s*"([^"]*)"') or ""
    local desc = trim(jstr_raw(obj, "description") or "", 400)
    if tmpl and tmpl ~= "" then
      out[#out+1] = { name = name, uri_template = tmpl, description = desc }
    end
  end
  return out
end

-- Prompts: [{name, description, args=[]}]
-- Extracts prompt argument schemas from prompts/list response — these are the
-- parameters prompt templates accept and represent injection/manipulation surface.
local function parse_prompts(body)
  if not body then return {} end
  local arr = body:match('"prompts"%s*:%s*(%b[])')
  if not arr then return {} end
  local out = {}
  for obj in arr:gmatch('%b{}') do
    local name = obj:match('"name"%s*:%s*"([^"]+)"')
    if name then
      local desc  = trim(jstr_raw(obj, "description") or "", 400)
      local args  = {}
      local aarr  = obj:match('"arguments"%s*:%s*(%b[])')
      if aarr then
        for aobj in aarr:gmatch('%b{}') do
          local aname = aobj:match('"name"%s*:%s*"([^"]+)"')
          local areq  = aobj:find('"required"%s*:%s*true') ~= nil
          if aname then
            args[#args+1] = areq and (aname .. "*") or aname
          end
        end
      end
      out[#out+1] = { name = name, description = desc, args = args }
    end
  end
  return out
end

-- Capability keys from initialize result body
local function parse_caps(body)
  if not body then return {} end
  local res_block = body:match('"result"%s*:%s*(%b{})') or body
  local cap_block = res_block:match('"capabilities"%s*:%s*(%b{})')
  if not cap_block then return {} end
  -- Strip nested objects/arrays before matching so sub-keys like "listChanged"
  -- don't appear as top-level capabilities.
  local inner = cap_block:match('^{(.*)}$') or cap_block
  local flat  = inner:gsub('%b{}', ''):gsub('%b[]', '')
  local caps  = {}
  for k in flat:gmatch('"([a-zA-Z][a-zA-Z0-9_]*)"%s*:') do
    caps[k] = true
  end
  return caps
end

-- Whether the server's "resources" capability advertises subscribe support
-- (push notifications when a subscribed resource changes) -- parse_caps()
-- deliberately flattens away nested sub-keys like this one, so it needs its
-- own targeted check rather than a caps["subscribe"] lookup.
local function resources_subscribe(body)
  if not body then return false end
  local res_block = body:match('"result"%s*:%s*(%b{})') or body
  local cap_block  = res_block:match('"capabilities"%s*:%s*(%b{})')
  if not cap_block then return false end
  local resources_block = cap_block:match('"resources"%s*:%s*(%b{})')
  if not resources_block then return false end
  return resources_block:find('"subscribe"%s*:%s*true') ~= nil
end

-- JSON-RPC error code from a stateless-protocol response body (e.g. "-32021").
-- -32020/-32021/-32022 are new in 2026-07-28 and are themselves proof of a
-- stateless-capable server, even when the request was rejected.
local function stateless_error_code(body)
  if not body then return nil end
  return body:match('"code"%s*:%s*(%-?%d+)')
end

-- Server identity from result._meta["io.modelcontextprotocol/serverInfo"] —
-- there is no initialize response to read it from under the stateless protocol.
local function stateless_server_info(body)
  if not body then return nil, nil end
  local res_block = body:match('"result"%s*:%s*(%b{})') or body
  local meta = res_block:match('"_meta"%s*:%s*(%b{})')
  if not meta then return nil, nil end
  local info = meta:match('"io%.modelcontextprotocol/serverInfo"%s*:%s*(%b{})')
  if not info then return nil, nil end
  return info:match('"name"%s*:%s*"([^"]*)"'), info:match('"version"%s*:%s*"([^"]*)"')
end

-- HTTP wrappers

local function json_post_opts(session_id)
  local h = {
    ["Content-Type"] = "application/json",
    ["Accept"]       = "application/json, text/event-stream",
    ["User-Agent"]   = "nmap-http-mcp-enum/1.0",
  }
  if session_id  then h["Mcp-Session-Id"] = session_id end
  if AUTH_HEADER then h[AUTH_HEADER]      = AUTH_VALUE  end
  return { timeout = TIMEOUT, header = h }
end

local function post_rpc(host, port, path, body, session_id)
  local ok, r = pcall(http.post, host, port, path, json_post_opts(session_id), nil, body)
  return (ok and r and r.status) and r or nil
end

-- 2026-07-28 stateless protocol: Mcp-Method rides on every request, Mcp-Name
-- on requests that name a tool/resource/prompt, MCP-Protocol-Version pins the
-- version — no Mcp-Session-Id since there is no session.
local function stateless_post_opts(method, name)
  local h = {
    ["Content-Type"]        = "application/json",
    ["Accept"]               = "application/json, text/event-stream",
    ["User-Agent"]           = "nmap-http-mcp-enum/1.0",
    ["MCP-Protocol-Version"] = STATELESS_VERSION,
    ["Mcp-Method"]           = method,
  }
  if name        then h["Mcp-Name"]  = name       end
  if AUTH_HEADER then h[AUTH_HEADER] = AUTH_VALUE  end
  return { timeout = TIMEOUT, header = h }
end

local function post_rpc_stateless(host, port, path, body, method, name)
  local ok, r = pcall(http.post, host, port, path, stateless_post_opts(method, name), nil, body)
  return (ok and r and r.status) and r or nil
end

local function get_req(host, port, path)
  local h = {
    ["User-Agent"] = "nmap-http-mcp-enum/1.0",
    ["Accept"]     = "application/json, text/event-stream, */*",
  }
  if AUTH_HEADER then h[AUTH_HEADER] = AUTH_VALUE end
  local ok, r = pcall(http.get, host, port, path, { timeout = TIMEOUT, header = h })
  return (ok and r and r.status) and r or nil
end

-- Pagination

-- poster defaults to post_rpc; try_sse passes a poster that redirects to the
-- open SSE stream when a server accepts requests asynchronously (see
-- make_sse_poster below) instead of answering the POST directly.
local function fetch_paged(host, port, endpoint, session_id, method, req_id, parser, poster)
  poster = poster or post_rpc
  local all    = {}
  local cursor = nil
  for _ = 1, MAX_PAGES do
    local req_body
    if cursor then
      req_body = string.format(
        '{"jsonrpc":"2.0","id":%d,"method":"%s","params":{"cursor":"%s"}}',
        req_id, method, cursor:gsub('"', '\\"'))
    else
      req_body = string.format(
        '{"jsonrpc":"2.0","id":%d,"method":"%s","params":{}}', req_id, method)
    end
    local r = poster(host, port, endpoint, req_body, session_id)
    if not r or r.status ~= 200 then break end
    local body = unwrap_sse(r.body or "")
    for _, item in ipairs(parser(body)) do all[#all+1] = item end
    cursor = next_cursor(body)
    if not cursor then break end
  end
  return all
end

-- Pagination — stateless protocol variant. Same nextCursor mechanic; each page
-- carries the full _meta block instead of a session_id.

local function fetch_paged_stateless(host, port, endpoint, method, name, req_id, parser)
  local all    = {}
  local cursor = nil
  for _ = 1, MAX_PAGES do
    local params = cursor
      and string.format('"cursor":"%s",%s', cursor:gsub('"', '\\"'), STATELESS_META)
      or STATELESS_META
    local req_body = string.format('{"jsonrpc":"2.0","id":%d,"method":"%s","params":{%s}}',
      req_id, method, params)
    local r = post_rpc_stateless(host, port, endpoint, req_body, method, name)
    if not r or r.status ~= 200 then break end
    local body = unwrap_sse(r.body or "")
    for _, item in ipairs(parser(body)) do all[#all+1] = item end
    cursor = next_cursor(body)
    if not cursor then break end
  end
  return all
end

-- .well-known/mcp discovery
-- Returns {endpoint=path, is_sse=bool} if the server advertises its transport,
-- or nil if the endpoint isn't present or parseable.
-- Routing: is_sse=true → try_sse first; is_sse=false/nil → try_streamable first.

local function discover_transport(host, port)
  local r = get_req(host, port, "/.well-known/mcp")
  if not r or r.status ~= 200 then return nil end
  local body = r.body or ""
  local ep = body:match('"endpoint"%s*:%s*"([^"]+)"')
          or body:match('"url"%s*:%s*"([^"]+)"')
  if not ep then return nil end
  local path = ep:match("https?://[^/]+(/.+)") or (ep:match("^/") and ep) or nil
  if not path then return nil end
  local transport_hint = body:match('"transport"%s*:%s*"([^"]+)"')
                      or body:match('"type"%s*:%s*"([^"]+)"')
  return { endpoint = path, is_sse = transport_hint and has(transport_hint, "sse") or false }
end

-- OAuth 2.0 Protected Resource Metadata (RFC 9728), advertised per the MCP
-- authorization spec via a resource_metadata parameter on the 401's
-- WWW-Authenticate header. Falls back to the conventional default path when
-- that parameter is absent — some servers point clients at the well-known
-- location without bothering to advertise it explicitly, and a client-side
-- implementation that only trusts the header parameter would miss them.
-- Reports a missing/empty authorization_servers as its own finding rather
-- than treating "metadata present" and "metadata complete" as the same
-- thing — MCP servers MUST include it, so an incomplete document is itself
-- a spec-violation worth surfacing, not just silently skipped.
local function oauth_metadata_summary(host, port, www_authenticate)
  local meta_url = www_authenticate:match('resource_metadata%s*=%s*"([^"]+)"')
  local path = meta_url and (meta_url:match("https?://[^/]+(/.+)") or meta_url:match("^(/.+)"))
            or "/.well-known/oauth-protected-resource"
  local r = get_req(host, port, path)
  if not r or r.status ~= 200 or has(hdr(r, "content-type"), "text/html") then return nil end
  local body = r.body or ""
  if not has(body, '"resource"') then return nil end
  local as_arr = body:match('"authorization_servers"%s*:%s*(%b[])')
  local servers = {}
  if as_arr then
    for s in as_arr:gmatch('"([^"]+)"') do servers[#servers+1] = s end
  end
  if #servers == 0 then
    return "protected-resource metadata present but authorization_servers is missing/empty — spec violation (MUST include at least one)"
  end
  return "authorization_server: " .. table.concat(servers, ", ")
end

-- Core MCP handshake

-- poster defaults to post_rpc; pass make_sse_poster(sse_sock) for servers
-- using the async SSE transport, where responses arrive as a pushed event on
-- the open stream rather than in the POST response itself.
local function handshake(host, port, endpoint, session_id, poster)
  poster = poster or post_rpc
  local r, body

  for _, init_body in ipairs({ INIT_LATEST, INIT_2025, INIT_2024 }) do
    r = poster(host, port, endpoint, init_body, session_id)
    if not r then return nil end
    if r.status == 200 then
      body = unwrap_sse(r.body or "")
      if has(body, '"result"') or not has(body, '"error"') then break end
    else
      break
    end
  end

  -- Confirmed MCP server behind auth: report the auth scheme from WWW-Authenticate,
  -- plus OAuth protected-resource metadata if the server advertises any.
  -- Confirmation: either Mcp-Session-Id (a server that got as far as assigning
  -- one before rejecting us) or, on the distinctive /mcp path specifically, a
  -- bare WWW-Authenticate is enough. The other candidate paths (/, /rpc, /api,
  -- /v1) are too generic to trust on a 401 alone -- a server that rejects
  -- *before* processing initialize structurally never has a session to set,
  -- so requiring Mcp-Session-Id alone would miss this case entirely, which
  -- defeats the point of OAuth discovery: its most common real use is
  -- scanning without credentials in the first place.
  if r.status == 401 and (hdr(r, "mcp-session-id") ~= ""
  or (endpoint == "/mcp" and hdr(r, "www-authenticate") ~= "")) then
    local www = hdr(r, "www-authenticate")
    local scheme = (www ~= "" and www:match("^(%S+)") or "unknown")
    local oauth = oauth_metadata_summary(host, port, www)
    local auth_msg = "401 Unauthorized — " .. scheme .. " required"
    if oauth then auth_msg = auth_msg .. "; " .. oauth end
    return { endpoint = endpoint,
             auth = auth_msg,
             caps = {}, tools = {}, resources = {}, resource_templates = {}, prompts = {} }
  end
  if r.status ~= 200 then return nil end

  body = unwrap_sse(r.body or "")
  if has(hdr(r, "content-type"), "text/html") then return nil end
  if not has(body, "protocolVersion") or not has(body, "jsonrpc") then return nil end
  if has(body, '"error"') and not has(body, '"result"') then return nil end

  local resp_session = hdr(r, "mcp-session-id")
  if resp_session ~= "" then session_id = resp_session end

  local proto     = jstr(body, "protocolVersion")
  local caps      = parse_caps(body)
  local subscribe = resources_subscribe(body)

  local srv_name, srv_ver
  do
    local res_block  = body:match('"result"%s*:%s*(%b{})') or body
    local info_block = res_block:match('"serverInfo"%s*:%s*(%b{})')
    if info_block then
      srv_name = info_block:match('"name"%s*:%s*"([^"]*)"')
      srv_ver  = info_block:match('"version"%s*:%s*"([^"]*)"')
    end
  end

  post_rpc(host, port, endpoint, INIT_NOTIF, session_id)

  local tools = fetch_paged(host, port, endpoint, session_id,
    "tools/list", 2, function(b) return parse_tools(b) end, poster)

  -- Fetch resources and resource templates from the same paginated response pages.
  local resources        = {}
  local resource_templates = {}
  do
    local cursor = nil
    for _ = 1, MAX_PAGES do
      local req_body = cursor
        and string.format(
          '{"jsonrpc":"2.0","id":3,"method":"resources/list","params":{"cursor":"%s"}}',
          cursor:gsub('"', '\\"'))
        or '{"jsonrpc":"2.0","id":3,"method":"resources/list","params":{}}'
      local r2 = poster(host, port, endpoint, req_body, session_id)
      if not r2 or r2.status ~= 200 then break end
      local b2 = unwrap_sse(r2.body or "")
      for _, item in ipairs(parse_resources(b2))           do resources[#resources+1]          = item end
      for _, item in ipairs(parse_resource_templates(b2))  do resource_templates[#resource_templates+1] = item end
      cursor = next_cursor(b2)
      if not cursor then break end
    end
  end

  local prompts = fetch_paged(host, port, endpoint, session_id,
    "prompts/list", 4, function(b) return parse_prompts(b) end, poster)

  for i = 1, math.min(#prompts, 5) do
    local p = prompts[i]
    local req = string.format(
      '{"jsonrpc":"2.0","id":5,"method":"prompts/get","params":{"name":"%s"}}',
      p.name:gsub('\\', '\\\\'):gsub('"', '\\"'))
    local r2 = poster(host, port, endpoint, req, session_id)
    if r2 and r2.status == 200 then
      local b2 = unwrap_sse(r2.body or "")
      local pending = pending_request(b2)
      if sampling_attempt(b2) then
        p.template = SAMPLING_WARNING
      elseif pending then
        p.template = "needs further input: " .. pending
      else
        local text = jstr_raw(b2, "text")
        if text and text ~= "" then p.template = trim(text, 400) end
      end
    end
  end

  return {
    endpoint           = endpoint,
    session_id         = session_id,
    proto              = proto,
    srv_name           = srv_name,
    srv_ver            = srv_ver,
    caps               = caps,
    subscribe          = subscribe,
    tools              = tools,
    resources          = resources,
    resource_templates = resource_templates,
    prompts            = prompts,
    auth               = AUTH_HEADER and "AUTHENTICATED" or "UNAUTHENTICATED",
    cors               = hdr(r, "access-control-allow-origin") == "*",
  }
end

-- Core MCP handshake — 2026-07-28 stateless protocol.
-- No initialize/session: bootstraps directly with a tools/list call carrying
-- the required _meta block. Server identity comes from result._meta.serverInfo.
-- A rejected bootstrap (-32020/-32021/-32022) is itself proof of a 2026-07-28
-- server, since those error codes did not exist before this spec revision.
--
-- A bare 401 is NOT treated as confirmation here (unlike the legacy path,
-- which requires an Mcp-Session-Id header alongside it): auth happens before
-- any protocol-specific processing, so a 401 to /mcp can't distinguish a
-- 2026-07-28 server from a legacy server or an unrelated authenticated API
-- guarding the same path. Overclaiming here produced false "stateless,
-- 2026-07-28" results against plain 2024-11-05/2025-06-18/2025-11-25 test
-- servers that happened to 401 the bootstrap call — verified against real
-- MCP test servers, not merely suspected. Likewise, a 200 response requires
-- resultType, which only exists on 2026-07-28+ responses — several real
-- legacy servers answer a bare tools/list (no prior initialize) with an
-- ordinary legacy-shaped result, which would otherwise false-match here too.

local function handshake_stateless(host, port, endpoint)
  local boot_req = string.format('{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{%s}}',
    STATELESS_META)
  local r = post_rpc_stateless(host, port, endpoint, boot_req, "tools/list")
  if not r then return nil end

  local body = unwrap_sse(r.body or "")

  if r.status == 400 then
    local code = stateless_error_code(body)
    if code ~= "-32020" and code ~= "-32021" and code ~= "-32022" then return nil end
    local msg = body:match('"message"%s*:%s*"([^"]*)"')
    return { endpoint = endpoint, proto = STATELESS_VERSION, stateless = true,
             caps = {}, tools = {}, resources = {}, resource_templates = {}, prompts = {},
             note = "stateless request rejected (" .. code .. "): " .. (msg or "no message"),
             auth = AUTH_HEADER and "AUTHENTICATED" or "UNAUTHENTICATED",
             cors = hdr(r, "access-control-allow-origin") == "*" }
  end
  if r.status ~= 200 then return nil end
  if has(hdr(r, "content-type"), "text/html") then return nil end
  if not has(body, '"jsonrpc"') or not has(body, '"resultType"')
  or not (has(body, '"result"') and has(body, '"tools"')) then
    return nil
  end

  local srv_name, srv_ver = stateless_server_info(body)

  local tools = fetch_paged_stateless(host, port, endpoint, "tools/list", nil, 2, parse_tools)

  local resources, resource_templates = {}, {}
  do
    local cursor = nil
    for _ = 1, MAX_PAGES do
      local params = cursor
        and string.format('"cursor":"%s",%s', cursor:gsub('"', '\\"'), STATELESS_META)
        or STATELESS_META
      local req_body = string.format(
        '{"jsonrpc":"2.0","id":3,"method":"resources/list","params":{%s}}', params)
      local r2 = post_rpc_stateless(host, port, endpoint, req_body, "resources/list")
      if not r2 or r2.status ~= 200 then break end
      local b2 = unwrap_sse(r2.body or "")
      for _, item in ipairs(parse_resources(b2))          do resources[#resources+1]          = item end
      for _, item in ipairs(parse_resource_templates(b2)) do resource_templates[#resource_templates+1] = item end
      cursor = next_cursor(b2)
      if not cursor then break end
    end
  end

  local prompts = fetch_paged_stateless(host, port, endpoint, "prompts/list", nil, 4, parse_prompts)

  for i = 1, math.min(#prompts, 5) do
    local p = prompts[i]
    local req = string.format(
      '{"jsonrpc":"2.0","id":5,"method":"prompts/get","params":{"name":"%s",%s}}',
      p.name:gsub('\\', '\\\\'):gsub('"', '\\"'), STATELESS_META)
    local r2 = post_rpc_stateless(host, port, endpoint, req, "prompts/get", p.name)
    if r2 and r2.status == 200 then
      local b2 = unwrap_sse(r2.body or "")
      local pending = pending_request(b2)
      if sampling_attempt(b2) then
        p.template = SAMPLING_WARNING
      elseif pending then
        p.template = "needs further input: " .. pending
      else
        local text = jstr_raw(b2, "text")
        if text and text ~= "" then p.template = trim(text, 400) end
      end
    end
  end

  return {
    endpoint           = endpoint,
    proto              = STATELESS_VERSION,
    stateless          = true,
    srv_name           = srv_name,
    srv_ver            = srv_ver,
    caps               = {},
    tools              = tools,
    resources          = resources,
    resource_templates = resource_templates,
    prompts            = prompts,
    auth               = AUTH_HEADER and "AUTHENTICATED" or "UNAUTHENTICATED",
    cors               = hdr(r, "access-control-allow-origin") == "*",
  }
end

-- Transport: Streamable HTTP

local _HTTP_ENDPOINTS = { "/mcp", "/", "/rpc", "/api", "/v1" }

local function try_streamable(host, port, discovered)
  local endpoints
  if discovered and not discovered.is_sse then
    endpoints = { discovered.endpoint }
    for _, ep in ipairs(_HTTP_ENDPOINTS) do
      if ep ~= discovered.endpoint then endpoints[#endpoints+1] = ep end
    end
  else
    endpoints = _HTTP_ENDPOINTS
  end
  for _, ep in ipairs(endpoints) do
    local res = handshake(host, port, ep)
    if res then res.transport = "streamable-http"; return res end
  end
end

-- Transport: Streamable HTTP, 2026-07-28 stateless protocol
-- Same candidate endpoints as legacy Streamable HTTP. SSE has no stateless
-- equivalent — streaming now goes through subscriptions/listen as an ordinary
-- request/response, not the old endpoint-discovery event stream.

local function try_stateless(host, port, discovered)
  local endpoints
  if discovered and not discovered.is_sse then
    endpoints = { discovered.endpoint }
    for _, ep in ipairs(_HTTP_ENDPOINTS) do
      if ep ~= discovered.endpoint then endpoints[#endpoints+1] = ep end
    end
  else
    endpoints = _HTTP_ENDPOINTS
  end
  for _, ep in ipairs(endpoints) do
    local res = handshake_stateless(host, port, ep)
    if res then res.transport = "streamable-http (stateless, 2026-07-28)"; return res end
  end
end

-- Transport: SSE (legacy)

local _SSE_PATHS = {
  "/sse", "/events", "/stream",
  "/v1/sse", "/api/sse", "/mcp/sse", "/mcp/stream",
}

-- Opens a raw socket and issues a GET for path directly (bypassing the http
-- library), stopping once the HTTP headers are read. Left open on success so
-- try_sse can read further pushed events from the same stream afterward —
-- needed because some servers answer the SSE-transport POST with a bare 202
-- Accepted and push the actual JSON-RPC response as a later event on this
-- connection rather than returning it in the POST response body. Returns the
-- open socket on a 200 text/event-stream response, else nil.
local function sse_open(host, port, path)
  local sock = nmap.new_socket()
  sock:set_timeout(TIMEOUT)
  if not sock:connect(host, port) then return nil end
  local h = "GET " .. path .. " HTTP/1.1\r\n" ..
            "Host: " .. (host.targetname or host.ip) .. "\r\n" ..
            "Accept: text/event-stream\r\n" ..
            "User-Agent: nmap-http-mcp-enum/1.0\r\n" ..
            "Connection: keep-alive\r\n"
  if AUTH_HEADER then h = h .. AUTH_HEADER .. ": " .. AUTH_VALUE .. "\r\n" end
  h = h .. "\r\n"
  if not sock:send(h) then sock:close(); return nil end
  local ok, headers = sock:receive_buf("\r\n\r\n", true)
  if not ok then sock:close(); return nil end
  if not headers:match("^HTTP/1%.[01] 200") or not has(headers, "text/event-stream") then
    sock:close()
    return nil
  end
  return sock
end

-- Reads the next SSE event's data: line from an open stream, tolerating
-- chunked-transfer-encoding framing bytes (hex chunk-size prefixes) mixed in
-- around it — those never match the "data:" pattern so they're harmlessly
-- skipped rather than needing a full chunked decoder. Returns the data
-- value, or nil on timeout/EOF.
local function sse_read_data(sock)
  for _ = 1, 20 do
    local ok, buf = sock:receive_buf("\n\n", true)
    if not ok then return nil end
    local data = buf:match('data%s*:%s*([^\r\n]+)')
    if data then return data end
  end
  return nil
end

-- Wraps post_rpc so that, when a server accepts a request asynchronously
-- (any response without a usable "result"/"error" body — commonly a bare
-- 202 Accepted with nothing in it), the actual response is instead read
-- from the already-open SSE stream as a pushed event. Falls back to the
-- POST's own response first, so servers that answer this transport
-- synchronously keep working exactly as before.
local function make_sse_poster(sse_sock)
  return function(host, port, path, body, session_id)
    local r = post_rpc(host, port, path, body, session_id)
    if r and r.status == 200 then
      local b = unwrap_sse(r.body or "")
      if has(b, '"result"') or has(b, '"error"') then return r end
    end
    local data = sse_read_data(sse_sock)
    if not data then return r end
    return { status = 200, header = (r and r.header) or {}, body = data }
  end
end

local function try_sse(host, port, discovered)
  local sse_paths
  if discovered and discovered.is_sse then
    sse_paths = { discovered.endpoint }
    for _, p in ipairs(_SSE_PATHS) do
      if p ~= discovered.endpoint then sse_paths[#sse_paths+1] = p end
    end
  else
    sse_paths = _SSE_PATHS
  end

  for _, sse_path in ipairs(sse_paths) do
    local sock = sse_open(host, port, sse_path)
    if not sock then goto next_sse end

    local data = sse_read_data(sock)
    if not data then sock:close(); goto next_sse end

    local msg_ep, session_id
    local uri = data:match('"uri"%s*:%s*"([^"]+)"')
             or data:match('^%s*(/[^%s\r\n]+)')
    if uri then
      msg_ep     = uri
      session_id = uri:match('[?&]session[Ii][Dd]=([^&\r\n]+)')
    end

    if not msg_ep then
      local uri2 = data:match('"method"%s*:%s*"endpoint"[^}]-"uri"%s*:%s*"([^"]+)"')
      if uri2 then
        msg_ep     = uri2
        session_id = uri2:match('session[Ii][Dd]=([^&\r\n"]+)')
      end
    end

    if not msg_ep and data:match("^/") and (has(data, "message") or has(data, "session")) then
      msg_ep = data:gsub('%s+$', '')
    end

    if msg_ep then
      local res = handshake(host, port, msg_ep, session_id, make_sse_poster(sock))
      if res then
        -- Left open (not closed here) so action() can reuse it for tool
        -- calls/resource reads under call=1/read=1 — same async-push
        -- requirement applies to those as to the handshake. Closed at the
        -- end of action() once nothing more will be read from it.
        res.transport = "sse"; res.sse_path = sse_path; res.sse_sock = sock
        return res
      end
      sock:close()
    else
      sock:close()
    end

    ::next_sse::
  end
end

-- Active probing

-- Build arguments from required parameter names. Using known keys with empty
-- string values gets past argument-presence validation into tool logic, often
-- producing richer error messages (path traversal hints, DB schema, etc.).
local function build_args(required)
  if not required or #required == 0 then return "{}" end
  local parts = {}
  for _, p in ipairs(required) do
    parts[#parts+1] = string.format('"%s":""', p:gsub('"', '\\"'))
  end
  return "{" .. table.concat(parts, ",") .. "}"
end

local function call_tool(host, port, endpoint, session_id, name, required, poster)
  poster = poster or post_rpc
  local req = string.format(
    '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"%s","arguments":%s}}',
    name:gsub('\\', '\\\\'):gsub('"', '\\"'), build_args(required))
  local r = poster(host, port, endpoint, req, session_id)
  if not r then return nil end
  local body = unwrap_sse(r.body or "")
  if r.status == 401 then return "401 Unauthorized" end
  if r.status == 403 then return "403 Forbidden"    end
  if sampling_attempt(body) then return SAMPLING_WARNING end
  local pending = pending_request(body)
  if pending then return "needs further input: " .. pending end
  if has(body, '"error"') then
    local msg = body:match('"message"%s*:%s*"([^"]*)"')
    return "error: " .. trim(msg or "(no message)", 120)
  end
  if r.status == 200 and has(body, '"result"') then
    local snippet = jstr_raw(body, "text")
    if snippet then return "ok: " .. trim(snippet, 80) end
    return "ok"
  end
  return nil
end

local function call_tool_stateless(host, port, endpoint, name, required)
  local req = string.format(
    '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"%s","arguments":%s,%s}}',
    name:gsub('\\', '\\\\'):gsub('"', '\\"'), build_args(required), STATELESS_META)
  local r = post_rpc_stateless(host, port, endpoint, req, "tools/call", name)
  if not r then return nil end
  local body = unwrap_sse(r.body or "")
  if r.status == 401 then return "401 Unauthorized" end
  if r.status == 403 then return "403 Forbidden"    end
  if sampling_attempt(body) then return SAMPLING_WARNING end
  local pending = pending_request(body)
  if pending then return "needs further input: " .. pending end
  if has(body, '"error"') then
    local msg = body:match('"message"%s*:%s*"([^"]*)"')
    return "error: " .. trim(msg or "(no message)", 120)
  end
  if r.status == 200 and has(body, '"result"') then
    local snippet = jstr_raw(body, "text")
    if snippet then return "ok: " .. trim(snippet, 80) end
    return "ok"
  end
  return nil
end

local function read_resource(host, port, endpoint, session_id, uri, poster)
  poster = poster or post_rpc
  local req = string.format(
    '{"jsonrpc":"2.0","id":20,"method":"resources/read","params":{"uri":"%s"}}',
    uri:gsub('\\', '\\\\'):gsub('"', '\\"'))
  local r = poster(host, port, endpoint, req, session_id)
  if not r then return nil end
  local body = unwrap_sse(r.body or "")
  if r.status == 401 then return "401 Unauthorized" end
  if r.status == 403 then return "403 Forbidden"    end
  if sampling_attempt(body) then return SAMPLING_WARNING end
  local pending = pending_request(body)
  if pending then return "needs further input: " .. pending end
  if has(body, '"error"') then
    local msg = body:match('"message"%s*:%s*"([^"]*)"')
    return "error: " .. trim(msg or "(no message)", 80)
  end
  if r.status == 200 and has(body, '"result"') then
    local snippet = jstr_raw(body, "text")
    if snippet then return trim(snippet, 150) end
    return "(non-text content)"
  end
  return nil
end

local function read_resource_stateless(host, port, endpoint, uri)
  local req = string.format(
    '{"jsonrpc":"2.0","id":20,"method":"resources/read","params":{"uri":"%s",%s}}',
    uri:gsub('\\', '\\\\'):gsub('"', '\\"'), STATELESS_META)
  local r = post_rpc_stateless(host, port, endpoint, req, "resources/read")
  if not r then return nil end
  local body = unwrap_sse(r.body or "")
  if r.status == 401 then return "401 Unauthorized" end
  if r.status == 403 then return "403 Forbidden"    end
  if sampling_attempt(body) then return SAMPLING_WARNING end
  local pending = pending_request(body)
  if pending then return "needs further input: " .. pending end
  if has(body, '"error"') then
    local msg = body:match('"message"%s*:%s*"([^"]*)"')
    return "error: " .. trim(msg or "(no message)", 80)
  end
  if r.status == 200 and has(body, '"result"') then
    local snippet = jstr_raw(body, "text")
    if snippet then return trim(snippet, 150) end
    return "(non-text content)"
  end
  return nil
end

-- Action

action = function(host, port)
  -- If http-ai-enum.nse already confirmed an MCP endpoint on this port, use it
  -- as the first candidate so we skip the discovery dance on known hosts.
  local reg_ep
  do
    local hr = (nmap.registry[host.ip] or {})[port.number] or {}
    reg_ep = hr["http_ai_enum_mcp"]
  end

  local discovered = reg_ep and { endpoint = reg_ep, is_sse = false }
                  or discover_transport(host, port)

  -- If .well-known/mcp says SSE, try SSE first (stateless has no SSE equivalent,
  -- so it's tried last there). Otherwise try the 2026-07-28 stateless protocol
  -- first, then fall back to the legacy stateful handshake, then SSE.
  local res
  if discovered and discovered.is_sse then
    res = try_sse(host, port, discovered)
    if not res then res = try_streamable(host, port, discovered) end
    if not res then res = try_stateless(host, port, discovered) end
  else
    res = try_stateless(host, port, discovered)
    if not res then res = try_streamable(host, port, discovered) end
    if not res then res = try_sse(host, port, discovered) end
  end
  if not res then return nil end

  -- Reused for tool calls/resource reads below when the SSE transport pushed
  -- the handshake response rather than answering synchronously — the same
  -- async requirement applies to every later request on this connection.
  local sse_poster = res.sse_sock and make_sse_poster(res.sse_sock) or nil

  local out = stdnse.output_table()

  if res.srv_name and res.srv_name ~= "" then
    local id = res.srv_name
    if res.srv_ver and res.srv_ver ~= "" then id = id .. " v" .. res.srv_ver end
    out["server"] = id
  end

  out["transport"] = res.transport
  out["endpoint"]  = res.endpoint

  local auth = res.auth or "unknown"
  if res.cors then auth = auth .. "  CORS:*" end
  out["auth"] = auth

  if res.proto      then out["protocol"]   = res.proto      end
  if res.session_id then out["session_id"] = res.session_id end
  if res.note       then out["note"]       = res.note       end

  local cap_names = {}
  for k in pairs(res.caps) do cap_names[#cap_names+1] = k end
  table.sort(cap_names)
  if #cap_names > 0 then out["capabilities"] = table.concat(cap_names, ", ") end

  -- Set below if a tool call, resource read, or prompt fetch turns up an
  -- unsolicited sampling/createMessage attempt (see sampling_attempt()).
  local sampling_seen = false

  do
    local notes = {}
    if res.caps.logging     then notes[#notes+1] = "logging: server can push log messages to connected clients" end
    if res.caps.completions then notes[#notes+1] = "completions: argument autocompletion reveals valid parameter values" end
    if res.subscribe        then notes[#notes+1] = "resources.subscribe: server supports push notifications on resource changes" end
    if #notes > 0 then out["capability notes"] = table.concat(notes, "; ") end
  end

  -- Tools

  if #res.tools > 0 then
    local tool_tbl = stdnse.output_table()
    local shown    = math.min(#res.tools, MAX_TOOLS)
    for i = 1, shown do
      local t   = res.tools[i]
      local ent = stdnse.output_table()
      if t.description ~= "" then ent["description"] = t.description end
      if #t.required > 0 then
        ent["params (required)"] = table.concat(t.required, ", ")
      end
      if t.annotations then ent["annotations"] = t.annotations end
      if DO_CALL then
        local cr = res.stateless
          and call_tool_stateless(host, port, res.endpoint, t.name, t.required)
          or call_tool(host, port, res.endpoint, res.session_id, t.name, t.required, sse_poster)
        if cr then
          ent["call"] = cr
          if cr == SAMPLING_WARNING then sampling_seen = true end
        end
      end
      tool_tbl[t.name] = ent
    end
    if #res.tools > MAX_TOOLS then
      tool_tbl["..."] = string.format("+%d more", #res.tools - MAX_TOOLS)
    end
    out[string.format("tools (%d)", #res.tools)] = tool_tbl
  end

  -- Resources

  if #res.resources > 0 then
    local res_tbl = stdnse.output_table()
    local shown   = math.min(#res.resources, 10)
    for i = 1, shown do
      local rv = res.resources[i]
      if DO_READ and i <= 3 then
        local ent = stdnse.output_table()
        if rv.name ~= "" and rv.name ~= rv.uri then ent["name"] = rv.name end
        local content = res.stateless
          and read_resource_stateless(host, port, res.endpoint, rv.uri)
          or read_resource(host, port, res.endpoint, res.session_id, rv.uri, sse_poster)
        if content then
          ent["content"] = content
          if content == SAMPLING_WARNING then sampling_seen = true end
        end
        res_tbl[rv.uri] = ent
      else
        res_tbl[rv.uri] = (rv.name ~= "" and rv.name ~= rv.uri) and rv.name or ""
      end
    end
    if #res.resources > 10 then
      res_tbl[string.format("(+%d more)", #res.resources - 10)] = ""
    end
    out[string.format("resources (%d)", #res.resources)] = res_tbl
  end

  -- Resource templates

  if #res.resource_templates > 0 then
    local tmpl_tbl = stdnse.output_table()
    for _, rv in ipairs(res.resource_templates) do
      local label = ""
      if rv.name ~= "" and rv.description ~= "" then
        label = rv.name .. " — " .. rv.description
      elseif rv.description ~= "" then
        label = rv.description
      elseif rv.name ~= "" then
        label = rv.name
      end
      tmpl_tbl[rv.uri_template] = label
    end
    out[string.format("resource templates (%d)", #res.resource_templates)] = tmpl_tbl
  end

  -- Prompts

  if #res.prompts > 0 then
    local pt = stdnse.output_table()
    for _, p in ipairs(res.prompts) do
      local ent = stdnse.output_table()
      if p.description and p.description ~= "" then ent["description"] = p.description end
      if #p.args > 0 then
        -- Args annotated with * are required. These are the injection surface.
        ent["args"] = table.concat(p.args, ", ")
      end
      if p.template then
        ent["template"] = p.template
        if p.template == SAMPLING_WARNING then sampling_seen = true end
      end
      pt[p.name] = ent
    end
    out[string.format("prompts (%d)", #res.prompts)] = pt
  end

  if sampling_seen then out["WARNING"] = SAMPLING_WARNING end

  if res.sse_sock then res.sse_sock:close() end

  return out
end
