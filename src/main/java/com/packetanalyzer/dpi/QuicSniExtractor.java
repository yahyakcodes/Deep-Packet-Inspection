package com.packetanalyzer.dpi;

import java.util.Optional;

/**
 * Best-effort SNI extraction from QUIC/HTTP3 Initial packets.
 * {@code DPI::QUICSNIExtractor} (SniExtractor.java) - this
 * explicitly a simplified heuristic, and this
 * keeps the same behavior rather than "improving" it into a real QUIC
 * CRYPTO-frame parser.
 * <p>Like {@link DnsExtractor}, this exists in the source but is not
 * called from {@link DpiEngine}'s main pipeline.
 */
public final class QuicSniExtractor {

    private QuicSniExtractor() {
    }

    public static boolean isQuicInitial(byte[] payload, int offset, int length) {
        if (length < 5) {
            return false;
        }
        int firstByte = payload[offset] & 0xFF;
        // Long header form requires the high bit set.
        return (firstByte & 0x80) != 0;
    }

    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (!isQuicInitial(payload, offset, length)) {
            return Optional.empty();
        }

        for (int i = 0; i + 50 < length; i++) {
            if ((payload[offset + i] & 0xFF) == 0x01) { // Client Hello handshake type
                int innerOffset = offset + i - 5;
                int innerLength = length - i + 5;
                if (innerOffset >= 0 && innerLength > 0) {
                    Optional<String> result = SniExtractor.extract(payload, innerOffset, innerLength);
                    if (result.isPresent()) {
                        return result;
                    }
                }
            }
        }

        return Optional.empty();
    }
}
