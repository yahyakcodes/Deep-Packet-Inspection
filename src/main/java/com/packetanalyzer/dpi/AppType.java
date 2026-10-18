package com.packetanalyzer.dpi;

import java.util.Locale;

/**
 * Application classification. {@code DPI::AppType} plus the
 * {@code appTypeToString} / {@code sniToAppType} functions in types.java.
 */
public enum AppType {
    UNKNOWN("Unknown"),
    HTTP("HTTP"),
    HTTPS("HTTPS"),
    DNS("DNS"),
    TLS("TLS"),
    QUIC("QUIC"),
    GOOGLE("Google"),
    FACEBOOK("Facebook"),
    YOUTUBE("YouTube"),
    TWITTER("Twitter/X"),
    INSTAGRAM("Instagram"),
    NETFLIX("Netflix"),
    AMAZON("Amazon"),
    MICROSOFT("Microsoft"),
    APPLE("Apple"),
    WHATSAPP("WhatsApp"),
    TELEGRAM("Telegram"),
    TIKTOK("TikTok"),
    SPOTIFY("Spotify"),
    ZOOM("Zoom"),
    DISCORD("Discord"),
    GITHUB("GitHub"),
    CLOUDFLARE("Cloudflare");

    private final String displayName;

    AppType(String displayName) {
        this.displayName = displayName;
    }

    /** Same string {@code appTypeToString()} returns in the original, used for display and --block-app matching. */
    public String getDisplayName() {
        return displayName;
    }

    /** Looks an app up by its exact display name, as used by {@code --block-app}. Returns null if unknown. */
    public static AppType fromDisplayName(String name) {
        for (AppType type : values()) {
            if (type.displayName.equals(name)) {
                return type;
            }
        }
        return null;
    }

    /**
     * Maps a detected SNI/Host domain to an application type. {@code sniToAppType()} in types.java, including its exact
     * substring-match ordering and lower-casing behavior.
     */
    public static AppType fromSni(String sni) {
        if (sni == null || sni.isEmpty()) {
            return UNKNOWN;
        }
        String s = sni.toLowerCase(Locale.ROOT);

        if (contains(s, "google") || contains(s, "gstatic") || contains(s, "googleapis")
                || contains(s, "ggpht") || contains(s, "gvt1")) {
            return GOOGLE;
        }
        if (contains(s, "youtube") || contains(s, "ytimg") || contains(s, "youtu.be")
                || contains(s, "yt3.ggpht")) {
            return YOUTUBE;
        }
        if (contains(s, "facebook") || contains(s, "fbcdn") || contains(s, "fb.com")
                || contains(s, "fbsbx") || contains(s, "meta.com")) {
            return FACEBOOK;
        }
        if (contains(s, "instagram") || contains(s, "cdninstagram")) {
            return INSTAGRAM;
        }
        if (contains(s, "whatsapp") || contains(s, "wa.me")) {
            return WHATSAPP;
        }
        if (contains(s, "twitter") || contains(s, "twimg") || contains(s, "x.com") || contains(s, "t.co")) {
            return TWITTER;
        }
        if (contains(s, "netflix") || contains(s, "nflxvideo") || contains(s, "nflximg")) {
            return NETFLIX;
        }
        if (contains(s, "amazon") || contains(s, "amazonaws") || contains(s, "cloudfront") || contains(s, "aws")) {
            return AMAZON;
        }
        if (contains(s, "microsoft") || contains(s, "msn.com") || contains(s, "office")
                || contains(s, "azure") || contains(s, "live.com") || contains(s, "outlook") || contains(s, "bing")) {
            return MICROSOFT;
        }
        if (contains(s, "apple") || contains(s, "icloud") || contains(s, "mzstatic") || contains(s, "itunes")) {
            return APPLE;
        }
        if (contains(s, "telegram") || contains(s, "t.me")) {
            return TELEGRAM;
        }
        if (contains(s, "tiktok") || contains(s, "tiktokcdn") || contains(s, "musical.ly") || contains(s, "bytedance")) {
            return TIKTOK;
        }
        if (contains(s, "spotify") || contains(s, "scdn.co")) {
            return SPOTIFY;
        }
        if (contains(s, "zoom")) {
            return ZOOM;
        }
        if (contains(s, "discord") || contains(s, "discordapp")) {
            return DISCORD;
        }
        if (contains(s, "github") || contains(s, "githubusercontent")) {
            return GITHUB;
        }
        if (contains(s, "cloudflare") || contains(s, "cf-")) {
            return CLOUDFLARE;
        }

        // SNI present but unrecognized: still mark it as encrypted HTTPS traffic.
        return HTTPS;
    }

    private static boolean contains(String haystack, String needle) {
        return haystack.contains(needle);
    }
}
