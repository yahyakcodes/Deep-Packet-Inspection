package com.packetanalyzer.dpi;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class AppTypeTest {

    @Test
    void classifiesKnownDomains() {
        assertEquals(AppType.GOOGLE, AppType.fromSni("www.google.com"));
        assertEquals(AppType.YOUTUBE, AppType.fromSni("www.youtube.com"));
        assertEquals(AppType.GITHUB, AppType.fromSni("github.com"));
        assertEquals(AppType.SPOTIFY, AppType.fromSni("open.spotify.com"));
    }

    @Test
    void unrecognizedSniFallsBackToHttps() {
        assertEquals(AppType.HTTPS, AppType.fromSni("example.com"));
    }

    @Test
    void emptySniIsUnknown() {
        assertEquals(AppType.UNKNOWN, AppType.fromSni(""));
    }

    @Test
    void fromDisplayNameRoundTrips() {
        assertEquals(AppType.YOUTUBE, AppType.fromDisplayName("YouTube"));
        assertNull(AppType.fromDisplayName("NotARealApp"));
    }
}
