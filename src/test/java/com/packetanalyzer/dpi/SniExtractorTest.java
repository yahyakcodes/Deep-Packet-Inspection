package com.packetanalyzer.dpi;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SniExtractorTest {

    /** Builds a minimal-but-structurally-valid TLS ClientHello with an SNI extension. */
    private static byte[] buildClientHelloWithSni(String hostname) throws IOException {
        byte[] hostBytes = hostname.getBytes(StandardCharsets.US_ASCII);

        ByteArrayOutputStream extBody = new ByteArrayOutputStream();
        // server_name_list entry: type(1)=hostname, length(2), name
        ByteArrayOutputStream nameEntry = new ByteArrayOutputStream();
        nameEntry.write(0x00); // name type = host_name
        writeU16(nameEntry, hostBytes.length);
        nameEntry.write(hostBytes);
        byte[] nameEntryBytes = nameEntry.toByteArray();

        writeU16(extBody, nameEntryBytes.length); // server_name_list length
        extBody.write(nameEntryBytes);
        byte[] extBodyBytes = extBody.toByteArray();

        ByteArrayOutputStream extensions = new ByteArrayOutputStream();
        writeU16(extensions, 0x0000); // extension type: server_name
        writeU16(extensions, extBodyBytes.length);
        extensions.write(extBodyBytes);
        byte[] extensionsBytes = extensions.toByteArray();

        ByteArrayOutputStream handshakeBody = new ByteArrayOutputStream();
        writeU16(handshakeBody, 0x0303); // client_version = TLS 1.2
        handshakeBody.write(new byte[32]); // random
        handshakeBody.write(0x00); // session_id_length = 0
        writeU16(handshakeBody, 0x0000); // cipher_suites_length = 0
        handshakeBody.write(0x00); // compression_methods_length = 0
        writeU16(handshakeBody, extensionsBytes.length); // extensions_length
        handshakeBody.write(extensionsBytes);
        byte[] handshakeBodyBytes = handshakeBody.toByteArray();

        ByteArrayOutputStream handshake = new ByteArrayOutputStream();
        handshake.write(0x01); // handshake type = client_hello
        write24(handshake, handshakeBodyBytes.length); // handshake length (3 bytes)
        handshake.write(handshakeBodyBytes);
        byte[] handshakeBytes = handshake.toByteArray();

        ByteArrayOutputStream record = new ByteArrayOutputStream();
        record.write(0x16); // content type = handshake
        writeU16(record, 0x0301); // record version
        writeU16(record, handshakeBytes.length); // record length
        record.write(handshakeBytes);

        return record.toByteArray();
    }

    private static void writeU16(ByteArrayOutputStream out, int value) {
        out.write((value >> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    private static void write24(ByteArrayOutputStream out, int value) {
        out.write((value >> 16) & 0xFF);
        out.write((value >> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    @Test
    void extractsSniFromClientHello() throws IOException {
        byte[] clientHello = buildClientHelloWithSni("example.com");

        assertTrue(SniExtractor.isTlsClientHello(clientHello, 0, clientHello.length));
        Optional<String> sni = SniExtractor.extract(clientHello, 0, clientHello.length);
        assertTrue(sni.isPresent());
        assertEquals("example.com", sni.get());
    }

    @Test
    void rejectsNonTlsPayload() {
        byte[] notTls = "GET / HTTP/1.1\r\n".getBytes(StandardCharsets.US_ASCII);
        assertTrue(SniExtractor.extract(notTls, 0, notTls.length).isEmpty());
    }
}
