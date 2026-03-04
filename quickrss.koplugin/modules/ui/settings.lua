-- QuickRSS: Settings UI
-- Fixed-size centered popup for configuring article limits.
-- Opened from the hamburger menu in QuickRSSUI.
--
-- Settings managed here:
--   items_per_feed     – how many recent articles to keep per feed after fetching
--   max_cache_age_days – treat cached articles as stale after N days (0 = never)

local Blitbuffer      = require("ffi/blitbuffer")
local CenterContainer = require("ui/widget/container/centercontainer")
local Config          = require("modules/data/config")
local Icons           = require("modules/ui/icons")
local Device          = require("device")
local FrameContainer  = require("ui/widget/container/framecontainer")
local Geom            = require("ui/geometry")
local InputContainer  = require("ui/widget/container/inputcontainer")
local InputDialog     = require("ui/widget/inputdialog")
local Size            = require("ui/size")
local SpinWidget      = require("ui/widget/spinwidget")
local SR              = require("modules/ui/settings_row")
local TextWidget      = require("ui/widget/textwidget")
local TitleBar        = require("ui/widget/titlebar")
local UIManager       = require("ui/uimanager")
local VerticalGroup   = require("ui/widget/verticalgroup")
local T               = require("ffi/util").template
local _               = require("gettext")

local Screen = Device.screen

local DEFAULT_FT_URL = "https://ftr.fivefilters.net/makefulltextfeed.php"
local PAD        = SR.PAD
local ROW_H      = SR.ROW_H
local VALUE_FACE = SR.VALUE_FACE

-- ─────────────────────────────────────────────────────────────────────────────
local SettingsUI = InputContainer:extend{
    name     = "quickrss_settings",
    on_close = nil,   -- optional callback fired when the popup closes
}

local function ageText(days)
    if days == 0 then return _("Never") end
    return T(_("%1 d"), days)
end

function SettingsUI:init()
    local screen_w = Screen:getWidth()
    local screen_h = Screen:getHeight()

    self.key_events = {
        Close = { { "Back" }, doc = "close settings" },
    }

    -- Current settings (merged with defaults)
    self.s = Config.getArticleSettings()

    -- ── Popup width ───────────────────────────────────────────────────────────
    local popup_w = math.floor(screen_w * 0.9)
    local inner_w = popup_w - PAD * 2

    -- ── Title bar ─────────────────────────────────────────────────────────────
    local title_bar = TitleBar:new{
        width            = popup_w,
        title            = Icons.SETTINGS .. "  " .. _("Settings"),
        with_bottom_line = true,
        close_callback   = function() self:onClose() end,
        show_parent      = self,
    }
    local title_bar_h = title_bar:getSize().h
    -- ── Value TextWidgets (stored so SpinWidget callbacks can update them) ────
    self.items_val = TextWidget:new{
        text = tostring(self.s.items_per_feed),
        face = VALUE_FACE,
    }
    self.age_val = TextWidget:new{
        text = ageText(self.s.max_cache_age_days),
        face = VALUE_FACE,
    }

    -- ── Row builder (shared) ────────────────────────────────────────────────
    local function makeRow(label, val_widget, on_tap)
        return SR.makeRow(inner_w, label, val_widget, on_tap)
    end

    -- ── Two rows with a separator between them ────────────────────────────────
    local row1 = makeRow(_("Articles per feed"), self.items_val,
                         function() self:_openItemsSpin() end)
    local row2 = makeRow(_("Max cache age"),     self.age_val,
                         function() self:_openAgeSpin() end)

    -- ── Image toggles ────────────────────────────────────────────────────────
    self.thumb_val = TextWidget:new{
        text = self.s.thumbnails_enabled and _("On") or _("Off"),
        face = VALUE_FACE,
    }
    local row3 = makeRow(_("Thumbnail images"), self.thumb_val,
                         function() self:_toggleThumbnails() end)

    self.art_img_val = TextWidget:new{
        text = self.s.article_images_enabled and _("On") or _("Off"),
        face = VALUE_FACE,
    }
    local row4 = makeRow(_("Article images"), self.art_img_val,
                         function() self:_toggleArticleImages() end)

    self.card_font_val = TextWidget:new{
        text = tostring(self.s.card_font_size),
        face = VALUE_FACE,
    }
    local row5 = makeRow(_("Card font size"), self.card_font_val,
                         function() self:_openCardFontSpin() end)

    -- ── Full-text extraction ────────────────────────────────────────────────
    self.ft_val = TextWidget:new{
        text = self.s.fulltext_enabled and _("On") or _("Off"),
        face = VALUE_FACE,
    }
    local row6 = makeRow(_("Full-text extraction"), self.ft_val,
                         function() self:_toggleFulltext() end)

    self.ft_url_val = TextWidget:new{
        text = self.s.fulltext_url == DEFAULT_FT_URL
            and _("Default") or _("Custom"),
        face = VALUE_FACE,
    }
    local row7 = makeRow(_("Extraction URL"), self.ft_url_val,
                         function() self:_editFulltextUrl() end)

    -- ── Custom DNS ────────────────────────────────────────────────────────────
    self.dns_val = TextWidget:new{
        text = self.s.custom_dns and _("On") or _("Off"),
        face = VALUE_FACE,
    }
    local row8 = makeRow(_("Custom DNS routing"), self.dns_val,
                         function() self:_toggleCustomDns() end)

    self.rows_group = VerticalGroup:new{
        align = "left",
        CenterContainer:new{ dimen = Geom:new{ w = popup_w, h = ROW_H }, row1 },
        CenterContainer:new{ dimen = Geom:new{ w = popup_w, h = ROW_H }, row2 },
        CenterContainer:new{ dimen = Geom:new{ w = popup_w, h = ROW_H }, row3 },
        CenterContainer:new{ dimen = Geom:new{ w = popup_w, h = ROW_H }, row4 },
        CenterContainer:new{ dimen = Geom:new{ w = popup_w, h = ROW_H }, row5 },
        CenterContainer:new{ dimen = Geom:new{ w = popup_w, h = ROW_H }, row6 },
        CenterContainer:new{ dimen = Geom:new{ w = popup_w, h = ROW_H }, row7 },
        CenterContainer:new{ dimen = Geom:new{ w = popup_w, h = ROW_H }, row8 },
    }

    -- ── Popup frame ───────────────────────────────────────────────────────────
    local rows_content_h = ROW_H * 8
    local popup_h        = title_bar_h + rows_content_h + 2 * Size.border.window

    local popup = FrameContainer:new{
        width      = popup_w,
        height     = popup_h,
        padding    = 0,
        margin     = 0,
        bordersize = Size.border.window,
        background = Blitbuffer.COLOR_WHITE,
        VerticalGroup:new{
            align = "left",
            title_bar,
            self.rows_group,
        },
    }

    -- Full-screen InputContainer so Back key is delivered correctly
    self[1] = CenterContainer:new{
        dimen = Geom:new{ w = screen_w, h = screen_h },
        popup,
    }

    -- Mirror what feed_list.lua does: queue a deferred setDirty so UIManager
    -- repaints the full popup once self.dimen is populated after the first
    -- paintTo() pass.  Without this the popup renders incompletely.
    UIManager:setDirty(self, function()
        return "ui", self.dimen
    end)
end

-- ── SpinWidget helpers ────────────────────────────────────────────────────────

function SettingsUI:_openItemsSpin()
    UIManager:show(SpinWidget:new{
        title_text      = _("Articles per feed"),
        info_text       = _("How many recent articles to keep from each feed"),
        value           = self.s.items_per_feed,
        value_min       = 5,
        value_max       = 100,
        value_step      = 5,
        value_hold_step = 10,
        default_value   = 20,
        callback = function(spin)
            self.s.items_per_feed = spin.value
            Config.saveArticleSettings(self.s)
            self.items_val:setText(tostring(spin.value))
            self.rows_group:resetLayout()
            UIManager:setDirty(self, function() return "ui", self.dimen end)
        end,
    })
end

function SettingsUI:_openAgeSpin()
    UIManager:show(SpinWidget:new{
        title_text      = _("Max cache age (days)"),
        info_text       = _("Show stale-cache prompt after this many days without a refresh.\n0 = never expire automatically."),
        value           = self.s.max_cache_age_days,
        value_min       = 0,
        value_max       = 365,
        value_step      = 1,
        value_hold_step = 7,
        default_value   = 30,
        callback = function(spin)
            self.s.max_cache_age_days = spin.value
            Config.saveArticleSettings(self.s)
            self.age_val:setText(ageText(spin.value))
            self.rows_group:resetLayout()
            UIManager:setDirty(self, function() return "ui", self.dimen end)
        end,
    })
end

function SettingsUI:_openCardFontSpin()
    UIManager:show(SpinWidget:new{
        title_text      = _("Card font size"),
        info_text       = _("Base font size for article cards in the feed list"),
        value           = self.s.card_font_size,
        value_min       = 10,
        value_max       = 22,
        value_step      = 1,
        value_hold_step = 2,
        default_value   = 14,
        callback = function(spin)
            self.s.card_font_size = spin.value
            Config.saveArticleSettings(self.s)
            self.card_font_val:setText(tostring(spin.value))
            self.rows_group:resetLayout()
            UIManager:setDirty(self, function() return "ui", self.dimen end)
        end,
    })
end

function SettingsUI:_toggleThumbnails()
    self.s.thumbnails_enabled = not self.s.thumbnails_enabled
    Config.saveArticleSettings(self.s)
    self.thumb_val:setText(self.s.thumbnails_enabled and _("On") or _("Off"))
    self.rows_group:resetLayout()
    UIManager:setDirty(self, function() return "ui", self.dimen end)
end

function SettingsUI:_toggleArticleImages()
    self.s.article_images_enabled = not self.s.article_images_enabled
    Config.saveArticleSettings(self.s)
    self.art_img_val:setText(self.s.article_images_enabled and _("On") or _("Off"))
    self.rows_group:resetLayout()
    UIManager:setDirty(self, function() return "ui", self.dimen end)
end

function SettingsUI:_toggleFulltext()
    self.s.fulltext_enabled = not self.s.fulltext_enabled
    Config.saveArticleSettings(self.s)
    self.ft_val:setText(self.s.fulltext_enabled and _("On") or _("Off"))
    self.rows_group:resetLayout()
    UIManager:setDirty(self, function() return "ui", self.dimen end)
end

function SettingsUI:_toggleCustomDns()
    self.s.custom_dns = not self.s.custom_dns
    Config.saveArticleSettings(self.s)
    self.dns_val:setText(self.s.custom_dns and _("On") or _("Off"))
    self.rows_group:resetLayout()
    UIManager:setDirty(self, function() return "ui", self.dimen end)
end

function SettingsUI:_editFulltextUrl()
    local dialog
    dialog = InputDialog:new{
        title      = _("Extraction service URL"),
        input      = self.s.fulltext_url,
        input_hint = DEFAULT_FT_URL,
        buttons    = {
            {
                {
                    text     = _("Cancel"),
                    id       = "close",
                    callback = function()
                        UIManager:close(dialog)
                    end,
                },
                {
                    text     = _("Restore default"),
                    callback = function()
                        self.s.fulltext_url = DEFAULT_FT_URL
                        Config.saveArticleSettings(self.s)
                        self.ft_url_val:setText(_("Default"))
                        self.rows_group:resetLayout()
                        UIManager:setDirty(self, function() return "ui", self.dimen end)
                        UIManager:close(dialog)
                    end,
                },
                {
                    text      = _("Save"),
                    is_enter_default = true,
                    callback  = function()
                        local val = dialog:getInputText()
                        if val and val ~= "" then
                            self.s.fulltext_url = val
                            Config.saveArticleSettings(self.s)
                            self.ft_url_val:setText(
                                val == DEFAULT_FT_URL and _("Default") or _("Custom"))
                            self.rows_group:resetLayout()
                            UIManager:setDirty(self, function() return "ui", self.dimen end)
                        end
                        UIManager:close(dialog)
                    end,
                },
            },
        },
    }
    UIManager:show(dialog)
    dialog:onShowKeyboard()
end

function SettingsUI:onClose()
    UIManager:close(self)
end

-- Called by UIManager after the widget is removed from the stack.
-- Forces a repaint of the area behind the popup so the article list
-- is restored cleanly without leaving ghost pixels.
function SettingsUI:onCloseWidget()
    UIManager:setDirty(nil, function()
        return "ui", self.dimen
    end)
    if self.on_close then self.on_close() end
end

return SettingsUI
