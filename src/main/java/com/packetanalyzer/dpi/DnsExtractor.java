package com.packetanalyzer.dpi;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Extracts the queried domain name from a DNS query message. Direct port
 * of {@code DPI::DNSExtractor} (sni_extractor.cpp).
 *
 * <p>Note: exactly as in the original project, this class is fully
 * implemented but not wired into the main DPI pipeline - {@link DpiEngine}
 * classifies port-53 traffic as {@link AppType#DNS} purely by port number,
 * the same as {@code dpi_mt.cpp}'s {@code classifyFlow()}. It's kept here
 * as available, working functionality for the same reason it exists in
 * the C++ sources.
 */
public final class DnsExtractor {

    private DnsExtractor() {
    }

    public static boolean isDnsQuery(byte[] payload, int offset, int length) {
        if (length < 12) {
            return false;
        }
        int flags = payload[offset + 2] & 0xFF;
        if ((flags & 0x80) != 0) {
            return false; // response, not a query
        }
        int qdcount = ((payload[offset + 4] & 0xFF) << 8) | (payload[offset + 5] & 0xFF);
        return qdcount != 0;
    }

    public static Optional<String> extractQuery(byte[] payload, int offset, int length) {
        if (!isDnsQuery(payload, offset, length)) {
            return Optional.empty();
        }

        int pos = 12;
        StringBuilder domain = new StringBuilder();

        while (pos < length) {
            int labelLength = payload[offset + pos] & 0xFF;
            if (labelLength == 0) {
                break;
            }
            if (labelLength > 63) {
                break; // compression pointer or invalid
            }
            pos++;
            if (pos + labelLength > length) {
                break;
            }
            if (domain.length() > 0) {
                domain.append('.');
            }
            domain.append(new String(payload, offset + pos, labelLength, StandardCharsets.US_ASCII));
            pos += labelLength;
        }

        return domain.length() == 0 ? Optional.empty() : Optional.of(domain.toString());
    }
}
