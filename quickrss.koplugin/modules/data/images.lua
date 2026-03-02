-- QuickRSS: Image Cache Utilities
-- Downloads and caches remote images to disk. Provides helper functions to
-- rewrite remote <img src> URLs in HTML to local filenames, and to strip
-- publisher-injected width/height/style attributes so CSS can control layout.
--
-- Public API:
--   Images.IMAGE_DIR                    path to the image cache directory
--   Images.downloadImage(url)           → local filename (relative to IMAGE_DIR) or nil
--   Images.localizeImages(html)         → html with remote src rewritten to local filenames
--   Images.constrainImages(html)        → html with width/height/style stripped from <img>

local DataStorage = require("datastorage")
local lfs         = require("libs/libkoreader-lfs")
local logger      = require("logger")
local ltn12       = require("ltn12")
local https       = require("ssl.https")
local socketutil  = require("socketutil")

local IMAGE_DIR = DataStorage:getSettingsDir() .. "/quickrss_images"
lfs.mkdir(IMAGE_DIR)  -- no-op if already exists

-- Non-cryptographic hash → stable 8-char hex filename prefix.
local function urlHash(url)
    local h = 5381
    for i = 1, #url do
        h = ((h * 33) + url:byte(i)) % 0x100000000
    end
    return string.format("%08x", h)
end

-- Best-effort extension extraction; defaults to "jpg".
local function guessExt(url)
    return url:match("%.(%a%a%a?%a?)%?")
        or url:match("%.(%a%a%a?%a?)$")
        or "jpg"
end

-- Download one image URL into IMAGE_DIR.  Returns the local filename (relative
-- to IMAGE_DIR) on success, or nil on failure.  Already-cached files are
-- returned immediately without a network request.
local function downloadImage(url)
    local fname = urlHash(url) .. "." .. guessExt(url)
    local fpath = IMAGE_DIR .. "/" .. fname

    -- Cache hit
    local f = io.open(fpath, "rb")
    if f then f:close(); return fname end

    -- Download with redirect following (up to 3 hops) and retry on transient
    -- network errors (DNS hiccups, timeouts) that are common on e-readers.
    local MAX_RETRIES = 2
    local sink, ok, code, headers

    for attempt = 1, MAX_RETRIES + 1 do
        local current_url = url
        local net_err = false
        for _ = 1, 3 do
            sink = {}
            socketutil:set_timeout(
                socketutil.LARGE_BLOCK_TIMEOUT,
                socketutil.LARGE_TOTAL_TIMEOUT
            )
            ok, code, headers = https.request{
                url  = current_url,
                sink = ltn12.sink.table(sink),
            }
            socketutil:reset_timeout()

            if not ok then
                net_err = true
                break
            end
            if code == 301 or code == 302 or code == 303
            or code == 307 or code == 308 then
                local location = headers and headers["location"]
                if not location or location == "" then
                    logger.warn("QuickRSS: redirect with no Location:", url, code)
                    return nil
                end
                logger.dbg("QuickRSS: image redirect", code, "→", location)
                current_url = location
            else
                break
            end
        end

        if net_err then
            if attempt <= MAX_RETRIES then
                logger.dbg("QuickRSS: image retry", attempt, "for:", url, code)
                os.execute("sleep 1")
            else
                logger.warn("QuickRSS: image download error:", url, code)
                return nil
            end
        elseif code ~= 200 then
            -- HTTP error (4xx/5xx) — no point retrying
            logger.warn("QuickRSS: image download failed:", url, "HTTP", code)
            return nil
        else
            break  -- success
        end
    end

    f = io.open(fpath, "wb")
    if not f then return nil end
    local write_ok, write_err = pcall(function()
        f:write(table.concat(sink))
    end)
    f:close()
    if not write_ok then
        os.remove(fpath)  -- clean up partial file
        logger.warn("QuickRSS: image write failed:", fpath, write_err)
        return nil
    end
    logger.dbg("QuickRSS: cached image", fname)
    return fname
end

-- Strip width/height/style attributes from <img> tags so CSS max-width can
-- take effect.  Publishers often embed explicit pixel dimensions that make
-- images overflow the viewport regardless of what the stylesheet says.
local function constrainImages(html)
    return html:gsub("(<[Ii][Mm][Gg]%s)([^>]*)(>)", function(open, attrs, close)
        attrs = attrs:gsub('%s*width%s*=%s*"[^"]*"', "")
        attrs = attrs:gsub("%s*width%s*=%s*'[^']*'", "")
        attrs = attrs:gsub('%s*height%s*=%s*"[^"]*"', "")
        attrs = attrs:gsub("%s*height%s*=%s*'[^']*'", "")
        attrs = attrs:gsub('%s*style%s*=%s*"[^"]*"', "")
        attrs = attrs:gsub("%s*style%s*=%s*'[^']*'", "")
        return open .. attrs .. close
    end)
end

-- Decode HTML entities in a URL extracted from an src attribute.
local function decodeUrl(url)
    return url:gsub("&amp;", "&"):gsub("&lt;", "<"):gsub("&gt;", ">")
              :gsub("&quot;", '"'):gsub("&apos;", "'")
end

-- Rewrite every remote <img src="https?://..."> in html to a local filename
-- relative to IMAGE_DIR.  Handles both double- and single-quoted src values.
local function localizeImages(html)
    -- double-quoted src
    html = html:gsub('([Ss][Rr][Cc]%s*=%s*)"(https?://[^"]+)"', function(eq, url)
        local fname = downloadImage(decodeUrl(url))
        return eq .. '"' .. (fname or url) .. '"'
    end)
    -- single-quoted src
    html = html:gsub("([Ss][Rr][Cc]%s*=%s*)'(https?://[^']+)'", function(eq, url)
        local fname = downloadImage(decodeUrl(url))
        return eq .. "'" .. (fname or url) .. "'"
    end)
    return html
end

return {
    IMAGE_DIR        = IMAGE_DIR,
    downloadImage    = downloadImage,
    localizeImages   = localizeImages,
    constrainImages  = constrainImages,
}
