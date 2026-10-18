package com.packetanalyzer.dpi;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Parses a TLS Client Hello to pull out the Server Name Indication (SNI)
 * extension - the plaintext hostname visible even in encrypted HTTPS
 * connections. {@code DPI::SNIExtractor} (SniExtractor.java).
 * <p>{@code payload}/{@code offset}/{@code length} together describe the
 * TCP payload slice to inspect.
 */
public final class SniExtractor {

    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_SNI = 0x0000;
    private static final int SNI_TYPE_HOSTNAME = 0x00;

    private SniExtractor() {
    }

    public static boolean isTlsClientHello(byte[] payload, int offset, int length) {
        if (length < 9) {
            return false;
        }
        if (u8(payload, offset) != CONTENT_TYPE_HANDSHAKE) {
            return false;
        }
        int version = readUint16BE(payload, offset + 1);
        if (version < 0x0300 || version > 0x0304) {
            return false;
        }
        int recordLength = readUint16BE(payload, offset + 3);
        if (recordLength > length - 5) {
            return false;
        }
        return u8(payload, offset + 5) == HANDSHAKE_CLIENT_HELLO;
    }

    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (!isTlsClientHello(payload, offset, length)) {
            return Optional.empty();
        }

        int pos = 5; // skip TLS record header, relative to offset

        // Handshake header: type (already checked) + 3-byte length
        pos += 4;

        // Client version (2 bytes) + Random (32 bytes)
        pos += 2;
        pos += 32;

        if (pos >= length) {
            return Optional.empty();
        }
        int sessionIdLength = u8(payload, offset + pos);
        pos += 1 + sessionIdLength;

        if (pos + 2 > length) {
            return Optional.empty();
        }
        int cipherSuitesLength = readUint16BE(payload, offset + pos);
        pos += 2 + cipherSuitesLength;

        if (pos >= length) {
            return Optional.empty();
        }
        int compressionMethodsLength = u8(payload, offset + pos);
        pos += 1 + compressionMethodsLength;

        if (pos + 2 > length) {
            return Optional.empty();
        }
        int extensionsLength = readUint16BE(payload, offset + pos);
        pos += 2;

        int extensionsEnd = pos + extensionsLength;
        if (extensionsEnd > length) {
            extensionsEnd = length; // truncated, try anyway
        }

        while (pos + 4 <= extensionsEnd) {
            int extensionType = readUint16BE(payload, offset + pos);
            int extensionLength = readUint16BE(payload, offset + pos + 2);
            pos += 4;

            if (pos + extensionLength > extensionsEnd) {
                break;
            }

            if (extensionType == EXTENSION_SNI) {
                if (extensionLength < 5) {
                    break;
                }
                int sniListLength = readUint16BE(payload, offset + pos);
                if (sniListLength < 3) {
                    break;
                }
                int sniType = u8(payload, offset + pos + 2);
                int sniLength = readUint16BE(payload, offset + pos + 3);

                if (sniType != SNI_TYPE_HOSTNAME) {
                    break;
                }
                if (sniLength > extensionLength - 5) {
                    break;
                }

                String sni = new String(payload, offset + pos + 5, sniLength, StandardCharsets.US_ASCII);
                return Optional.of(sni);
            }

            pos += extensionLength;
        }

        return Optional.empty();
    }

    private static int u8(byte[] data, int index) {
        return data[index] & 0xFF;
    }

    private static int readUint16BE(byte[] data, int index) {
        return ((data[index] & 0xFF) << 8) | (data[index + 1] & 0xFF);
    }
}
