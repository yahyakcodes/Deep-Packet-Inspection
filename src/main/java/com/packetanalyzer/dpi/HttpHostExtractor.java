package com.packetanalyzer.dpi;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Extracts the {@code Host:} header from a plaintext HTTP request.
 * {@code DPI::HTTPHostExtractor} (sni_extractor.java).
 */
public final class HttpHostExtractor {

    private static final String[] METHODS = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};

    private HttpHostExtractor() {
    }

    public static boolean isHttpRequest(byte[] payload, int offset, int length) {
        if (length < 4) {
            return false;
        }
        for (String method : METHODS) {
            boolean match = true;
            for (int i = 0; i < 4; i++) {
                if ((payload[offset + i] & 0xFF) != method.charAt(i)) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return true;
            }
        }
        return false;
    }

    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (!isHttpRequest(payload, offset, length)) {
            return Optional.empty();
        }

        for (int i = 0; i + 6 < length; i++) {
            int b0 = payload[offset + i] & 0xFF;
            int b1 = payload[offset + i + 1] & 0xFF;
            int b2 = payload[offset + i + 2] & 0xFF;
            int b3 = payload[offset + i + 3] & 0xFF;
            int b4 = payload[offset + i + 4] & 0xFF;

            if ((b0 == 'H' || b0 == 'h') && (b1 == 'o' || b1 == 'O')
                    && (b2 == 's' || b2 == 'S') && (b3 == 't' || b3 == 'T') && b4 == ':') {

                int start = i + 5;
                while (start < length && (payload[offset + start] == ' ' || payload[offset + start] == '\t')) {
                    start++;
                }

                int end = start;
                while (end < length && payload[offset + end] != '\r' && payload[offset + end] != '\n') {
                    end++;
                }

                if (end > start) {
                    String host = new String(payload, offset + start, end - start, StandardCharsets.US_ASCII);
                    int colon = host.indexOf(':');
                    if (colon != -1) {
                        host = host.substring(0, colon);
                    }
                    return Optional.of(host);
                }
            }
        }

        return Optional.empty();
    }
}
