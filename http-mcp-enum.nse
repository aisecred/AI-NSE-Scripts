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
  3. SSE (legacy)     — GET /sse, /events, /stream, /v1/sse, /api/sse, /mcp/sse, etc.

For each discovered MCP server performs the full JSON-RPC handshake:
  initialize (2025-03-26 with 2024-11-05 fallback)
  → notifications/initialized
  → tools/list (paginated) + inputSchema required-param extraction
  → resources/list (paginated, static URIs + URI templates)
  → prompts/list (paginated) + prompts/get for each prompt

Security signals surfaced automatically:
  auth:         UNAUTHENTICATED / 401 scheme / 403
  CORS:*        Access-Control-Allow-Origin: * on the MCP endpoint
  WARNING:      server advertises sampling capability (can request LLM calls from clients)

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

local INIT_2025 = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":' ..
  '{"protocolVersion":"2025-03-26","capabilities":{},' ..
  '"clientInfo":{"name":"nmap-http-mcp-enum","version":"1.0"}}}'

local INIT_2024 = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":' ..
  '{"protocolVersion":"2024-11-05","capabilities":{},' ..
  '"clientInfo":{"name":"nmap-http-mcp-enum","version":"1.0"}}}'

local INIT_NOTIF = '{"jsonrpc":"2.0","method":"notifications/initialized"}'

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

-- JSON parsers

-- Tools: [{name, description, required=[]}]
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
            out[#out+1] = { name = name, description = desc, required = required }
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

local function fetch_paged(host, port, endpoint, session_id, method, req_id, parser)
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
    local r = post_rpc(host, port, endpoint, req_body, session_id)
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

-- Core MCP handshake

local function handshake(host, port, endpoint, session_id)
  local r, body

  for _, init_body in ipairs({ INIT_2025, INIT_2024 }) do
    r = post_rpc(host, port, endpoint, init_body, session_id)
    if not r then return nil end
    if r.status == 200 then
      body = unwrap_sse(r.body or "")
      if has(body, '"result"') or not has(body, '"error"') then break end
    else
      break
    end
  end

  -- Confirmed MCP server behind auth: report the auth scheme from WWW-Authenticate.
  if r.status == 401 and hdr(r, "mcp-session-id") ~= "" then
    local www = hdr(r, "www-authenticate")
    local scheme = (www ~= "" and www:match("^(%S+)") or "unknown")
    return { endpoint = endpoint,
             auth = "401 Unauthorized — " .. scheme .. " required",
             caps = {}, tools = {}, resources = {}, resource_templates = {}, prompts = {} }
  end
  if r.status ~= 200 then return nil end

  body = unwrap_sse(r.body or "")
  if has(hdr(r, "content-type"), "text/html") then return nil end
  if not has(body, "protocolVersion") or not has(body, "jsonrpc") then return nil end
  if has(body, '"error"') and not has(body, '"result"') then return nil end

  local resp_session = hdr(r, "mcp-session-id")
  if resp_session ~= "" then session_id = resp_session end

  local proto = jstr(body, "protocolVersion")
  local caps  = parse_caps(body)

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
    "tools/list", 2, function(b) return parse_tools(b) end)

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
      local r2 = post_rpc(host, port, endpoint, req_body, session_id)
      if not r2 or r2.status ~= 200 then break end
      local b2 = unwrap_sse(r2.body or "")
      for _, item in ipairs(parse_resources(b2))           do resources[#resources+1]          = item end
      for _, item in ipairs(parse_resource_templates(b2))  do resource_templates[#resource_templates+1] = item end
      cursor = next_cursor(b2)
      if not cursor then break end
    end
  end

  local prompts = fetch_paged(host, port, endpoint, session_id,
    "prompts/list", 4, function(b) return parse_prompts(b) end)

  for i = 1, math.min(#prompts, 5) do
    local p = prompts[i]
    local req = string.format(
      '{"jsonrpc":"2.0","id":5,"method":"prompts/get","params":{"name":"%s"}}',
      p.name:gsub('\\', '\\\\'):gsub('"', '\\"'))
    local r2 = post_rpc(host, port, endpoint, req, session_id)
    if r2 and r2.status == 200 then
      local text = jstr_raw(unwrap_sse(r2.body or ""), "text")
      if text and text ~= "" then p.template = trim(text, 400) end
    end
  end

  return {
    endpoint           = endpoint,
    session_id         = session_id,
    proto              = proto,
    srv_name           = srv_name,
    srv_ver            = srv_ver,
    caps               = caps,
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

-- Transport: SSE (legacy)

local _SSE_PATHS = {
  "/sse", "/events", "/stream",
  "/v1/sse", "/api/sse", "/mcp/sse", "/mcp/stream",
}

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
    local r = get_req(host, port, sse_path)
    if not r then goto next_sse end
    if not has(hdr(r, "content-type"), "text/event-stream") then goto next_sse end

    local body = r.body or ""
    local msg_ep, session_id

    local data_line = body:match('event%s*:%s*endpoint[^\n]*\n[^\n]*data%s*:%s*([^\r\n]+)')
    if data_line then
      local uri = data_line:match('"uri"%s*:%s*"([^"]+)"')
               or data_line:match('^%s*(/[^%s\r\n]+)')
      if uri then
        msg_ep     = uri
        session_id = uri:match('[?&]session[Ii][Dd]=([^&\r\n]+)')
      end
    end

    if not msg_ep then
      local uri = body:match('"method"%s*:%s*"endpoint"[^}]-"uri"%s*:%s*"([^"]+)"')
      if uri then
        msg_ep     = uri
        session_id = uri:match('session[Ii][Dd]=([^&\r\n"]+)')
      end
    end

    if not msg_ep then
      local plain = body:match('data%s*:%s*(/[^\r\n]+)')
      if plain and (has(plain, "message") or has(plain, "session")) then
        msg_ep = plain:gsub('%s+$', '')
      end
    end

    if msg_ep then
      local res = handshake(host, port, msg_ep, session_id)
      if res then res.transport = "sse"; res.sse_path = sse_path; return res end
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

local function call_tool(host, port, endpoint, session_id, name, required)
  local req = string.format(
    '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"%s","arguments":%s}}',
    name:gsub('\\', '\\\\'):gsub('"', '\\"'), build_args(required))
  local r = post_rpc(host, port, endpoint, req, session_id)
  if not r then return nil end
  local body = unwrap_sse(r.body or "")
  if r.status == 401 then return "401 Unauthorized" end
  if r.status == 403 then return "403 Forbidden"    end
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

local function read_resource(host, port, endpoint, session_id, uri)
  local req = string.format(
    '{"jsonrpc":"2.0","id":20,"method":"resources/read","params":{"uri":"%s"}}',
    uri:gsub('\\', '\\\\'):gsub('"', '\\"'))
  local r = post_rpc(host, port, endpoint, req, session_id)
  if not r then return nil end
  local body = unwrap_sse(r.body or "")
  if r.status == 401 then return "401 Unauthorized" end
  if r.status == 403 then return "403 Forbidden"    end
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

  -- If .well-known/mcp says SSE, try SSE first; otherwise Streamable HTTP first.
  local res
  if discovered and discovered.is_sse then
    res = try_sse(host, port, discovered)
    if not res then res = try_streamable(host, port, discovered) end
  else
    res = try_streamable(host, port, discovered)
    if not res then res = try_sse(host, port, discovered) end
  end
  if not res then return nil end

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

  local cap_names = {}
  for k in pairs(res.caps) do cap_names[#cap_names+1] = k end
  table.sort(cap_names)
  if #cap_names > 0 then out["capabilities"] = table.concat(cap_names, ", ") end

  if res.caps.sampling then
    out["WARNING"] = "sampling capability — server can invoke LLM calls on connected clients"
  end

  do
    local notes = {}
    if res.caps.logging     then notes[#notes+1] = "logging: server can push log messages to connected clients" end
    if res.caps.completions then notes[#notes+1] = "completions: argument autocompletion reveals valid parameter values" end
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
      if DO_CALL then
        local cr = call_tool(host, port, res.endpoint, res.session_id, t.name, t.required)
        if cr then ent["call"] = cr end
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
        local content = read_resource(host, port, res.endpoint, res.session_id, rv.uri)
        if content then ent["content"] = content end
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
      if p.template then ent["template"] = p.template end
      pt[p.name] = ent
    end
    out[string.format("prompts (%d)", #res.prompts)] = pt
  end

  return out
end
