-- QuickRSS: Custom DNS Resolver
-- Bypasses the system DNS resolver by sending UDP queries directly to
-- public DNS servers (Google 8.8.8.8, Cloudflare 1.1.1.1).  On some
-- e-readers the system resolver degrades after sustained use, causing
-- "host not found" errors.  This module provides a transparent fix.
--
-- Public API:
--   DNS.install()        patch socket.tcp so connect() uses custom DNS
--   DNS.uninstall()      restore original socket.tcp
--   DNS.resolve(host)    manual resolve; returns ip_string or nil, err

local logger = require("logger")

local DNS = {}

-- ── Configuration ───────────────────────────────────────────────────────────
local SERVERS     = { "8.8.8.8", "1.1.1.1" }
local TIMEOUT     = 3       -- seconds per server
local DEFAULT_TTL = 300     -- cache TTL when response has none
local MIN_TTL     = 60
local MAX_TTL     = 600

-- ── Session cache ───────────────────────────────────────────────────────────
local _cache = {}

local function cacheGet(hostname)
    local entry = _cache[hostname]
    if entry and os.time() < entry.expires then
        return entry.ip
    end
    _cache[hostname] = nil
    return nil
end

local function cacheSet(hostname, ip, ttl)
    if not ttl or ttl < MIN_TTL then ttl = DEFAULT_TTL end
    if ttl > MAX_TTL then ttl = MAX_TTL end
    _cache[hostname] = { ip = ip, expires = os.time() + ttl }
end

-- ── Binary helpers ──────────────────────────────────────────────────────────
local function readU16(data, offset)
    return string.byte(data, offset) * 256 + string.byte(data, offset + 1)
end

local function readU32(data, offset)
    return string.byte(data, offset)     * 16777216
         + string.byte(data, offset + 1) * 65536
         + string.byte(data, offset + 2) * 256
         + string.byte(data, offset + 3)
end

local function writeU16(n)
    return string.char(math.floor(n / 256) % 256, n % 256)
end

-- ── DNS query builder ───────────────────────────────────────────────────────
-- Encode a hostname as a DNS QNAME (length-prefixed labels + NUL terminator).
local function encodeName(hostname)
    local parts = {}
    for label in hostname:gmatch("[^%.]+") do
        parts[#parts + 1] = string.char(#label) .. label
    end
    parts[#parts + 1] = "\0"
    return table.concat(parts)
end

-- Build a DNS A-record query packet.
-- Returns (packet_string, transaction_id).
local function buildQuery(hostname)
    local id = math.random(0, 65535)
    local header = writeU16(id)
        .. "\x01\x00"      -- flags: standard query, recursion desired
        .. "\x00\x01"      -- QDCOUNT = 1
        .. "\x00\x00"      -- ANCOUNT = 0
        .. "\x00\x00"      -- NSCOUNT = 0
        .. "\x00\x00"      -- ARCOUNT = 0
    local question = encodeName(hostname)
        .. "\x00\x01"      -- QTYPE  = A (IPv4)
        .. "\x00\x01"      -- QCLASS = IN
    return header .. question, id
end

-- ── DNS response parser ─────────────────────────────────────────────────────
-- Skip past a DNS name at the given offset (1-based).
-- Handles both label sequences and compression pointers.
local function skipName(data, offset)
    while offset <= #data do
        local len = string.byte(data, offset)
        if len == 0 then
            return offset + 1
        elseif len >= 0xC0 then
            return offset + 2   -- compression pointer = 2 bytes
        else
            offset = offset + 1 + len
        end
    end
    return nil
end

-- Parse a DNS response and extract the first A record.
-- Returns (ip_string, ttl) on success, or (nil, error_string) on failure.
local function parseResponse(data, expected_id)
    if not data or #data < 12 then
        return nil, "response too short"
    end

    local id = readU16(data, 1)
    if id ~= expected_id then
        return nil, "transaction ID mismatch"
    end

    local flags = readU16(data, 3)
    local rcode = flags % 16
    if rcode ~= 0 then
        return nil, "DNS error RCODE=" .. rcode
    end

    local qdcount = readU16(data, 5)
    local ancount = readU16(data, 7)

    if ancount == 0 then
        return nil, "no answer records"
    end

    -- Skip the question section
    local offset = 13   -- byte after 12-byte header (1-based)
    for _ = 1, qdcount do
        offset = skipName(data, offset)
        if not offset then return nil, "malformed question" end
        offset = offset + 4   -- skip QTYPE + QCLASS
    end

    -- Parse answer records looking for TYPE=A
    for _ = 1, ancount do
        if offset > #data then return nil, "truncated answer" end
        offset = skipName(data, offset)
        if not offset then return nil, "malformed answer name" end

        if offset + 10 > #data then return nil, "truncated answer record" end

        local rtype    = readU16(data, offset)
        local ttl      = readU32(data, offset + 4)
        local rdlength = readU16(data, offset + 8)
        offset = offset + 10

        if rtype == 1 and rdlength == 4 then
            -- A record: 4 bytes = IPv4 address
            if offset + 3 > #data then return nil, "truncated A record" end
            local ip = string.format("%d.%d.%d.%d",
                string.byte(data, offset),
                string.byte(data, offset + 1),
                string.byte(data, offset + 2),
                string.byte(data, offset + 3))
            return ip, ttl
        else
            offset = offset + rdlength
        end
    end

    return nil, "no A record in response"
end

-- ── Public resolve function ─────────────────────────────────────────────────
function DNS.resolve(hostname)
    -- Already an IP
    if hostname:match("^%d+%.%d+%.%d+%.%d+$") then
        return hostname
    end

    -- Cache hit
    local cached = cacheGet(hostname)
    if cached then return cached end

    local socket = require("socket")
    local query, txid = buildQuery(hostname)

    for _, server in ipairs(SERVERS) do
        local udp = socket.udp()
        if udp then
            udp:settimeout(TIMEOUT)
            local ok, err = udp:sendto(query, server, 53)
            if ok then
                local response = udp:receive()
                if response then
                    local ip, ttl = parseResponse(response, txid)
                    if ip then
                        udp:close()
                        cacheSet(hostname, ip, ttl)
                        logger.dbg("QuickRSS DNS:", hostname, "->", ip,
                                   "(via", server .. ")")
                        return ip
                    end
                end
            end
            udp:close()
        end
    end

    logger.warn("QuickRSS DNS: failed to resolve", hostname)
    return nil, "DNS resolution failed for " .. hostname
end

-- ── TCP connect interception ────────────────────────────────────────────────
local _installed = false
local _real_tcp  = nil

-- Create a proxy wrapping a real TCP socket userdata.
-- LuaSec does `getmetatable(sock).__index.method` so __index MUST be a table,
-- not a function.  We use a nested metatable on that index table to delegate
-- unknown lookups to the real socket.
local function wrapSocket(sock)
    local real_connect = sock.connect

    -- This table IS the __index of the proxy's metatable.  LuaSec can index
    -- into it directly.  Our overridden methods live here; everything else
    -- falls through via its own __index metamethod to the real socket.
    local index_tbl = setmetatable({
        connect = function(_, address, port)
            if not address:match("^%d+%.%d+%.%d+%.%d+$") then
                local ip = DNS.resolve(address)
                if ip then
                    address = ip
                else
                    logger.dbg("QuickRSS DNS: resolve failed for", address,
                               "— falling back to system resolver")
                end
            end
            return real_connect(sock, address, port)
        end,
    }, {
        __index = function(_, key)
            local v = sock[key]
            if type(v) == "function" then
                return function(_, ...)
                    return v(sock, ...)
                end
            end
            return v
        end,
    })

    return setmetatable({}, {
        __index    = index_tbl,
        __newindex = index_tbl,
        __tostring = function() return tostring(sock) end,
    })
end

function DNS.install()
    if _installed then return end
    local socket = require("socket")
    _real_tcp = socket.tcp

    socket.tcp = function()
        local sock = _real_tcp()
        if not sock then return nil end
        return wrapSocket(sock)
    end

    _cache = {}
    _installed = true
    logger.info("QuickRSS DNS: custom resolver installed")
end

function DNS.uninstall()
    if not _installed then return end
    local socket = require("socket")
    socket.tcp = _real_tcp
    _real_tcp = nil
    _cache = {}
    _installed = false
    logger.info("QuickRSS DNS: custom resolver uninstalled")
end

-- Seed RNG once at module load
math.randomseed(os.time() + (os.clock() * 1000))

return DNS
