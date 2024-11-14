package io.smallrye.certs.pem.der;

import org.junit.jupiter.api.Test;
import java.util.HexFormat;
import static org.junit.jupiter.api.Assertions.*;

class ASN1ObjectIdentifierTest {

    @Test
    void testOID_1_2_840_10040_4_1() {
        ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.OID_1_2_840_10040_4_1;
        byte[] expected = HexFormat.of().parseHex("2a8648ce380401");
        assertArrayEquals(expected, oid.value(), "OID 1.2.840.10040.4.1 encoding mismatch");
    }

    @Test
    void testOID_1_2_840_113549_1_1_1() {
        ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.OID_1_2_840_113549_1_1_1;
        byte[] expected = HexFormat.of().parseHex("2A864886F70D010101");
        assertArrayEquals(expected, oid.value(), "OID 1.2.840.113549.1.1.1 encoding mismatch");
    }

    @Test
    void testOID_1_2_840_113549_1_1_10() {
        ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.OID_1_2_840_113549_1_1_10;
        byte[] expected = HexFormat.of().parseHex("2a864886f70d01010a");
        assertArrayEquals(expected, oid.value(), "OID 1.2.840.113549.1.1.10 encoding mismatch");
    }

    @Test
    void testOID_1_3_101_110() {
        ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.OID_1_3_101_110;
        byte[] expected = HexFormat.of().parseHex("2b656e");
        assertArrayEquals(expected, oid.value(), "OID 1.3.101.110 encoding mismatch");
    }

    @Test
    void testOID_1_3_101_111() {
        ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.OID_1_3_101_111;
        byte[] expected = HexFormat.of().parseHex("2b656f");
        assertArrayEquals(expected, oid.value(), "OID 1.3.101.111 encoding mismatch");
    }

    @Test
    void testOID_1_3_101_112() {
        ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.OID_1_3_101_112;
        byte[] expected = HexFormat.of().parseHex("2b6570");
        assertArrayEquals(expected, oid.value(), "OID 1.3.101.112 encoding mismatch");
    }

    @Test
    void testOID_1_3_101_113() {
        ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.OID_1_3_101_113;
        byte[] expected = HexFormat.of().parseHex("2b6571");
        assertArrayEquals(expected, oid.value(), "OID 1.3.101.113 encoding mismatch");
    }

    @Test
    void testOID_1_2_840_10045_2_1() {
        ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.OID_1_2_840_10045_2_1;
        byte[] expected = HexFormat.of().parseHex("2a8648ce3d0201");
        assertArrayEquals(expected, oid.value(), "OID 1.2.840.10045.2.1 encoding mismatch");
    }

    @Test
    void testOID_1_3_132_0_34() {
        ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.OID_1_3_132_0_34;
        byte[] expected = HexFormat.of().parseHex("2b81040022");
        assertArrayEquals(expected, oid.value(), "OID 1.3.132.0.34 encoding mismatch");
    }

    @Test
    void testCustomOIDCreation() {
        ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.from("2a8648", "foo");
        byte[] expected = HexFormat.of().parseHex("2a8648");
        assertArrayEquals(expected, oid.value(), "Custom OID encoding mismatch");
        assertEquals("foo", oid.algorithmId(), "Custom OID algorithm ID mismatch");
    }

    @Test
    void testGetAlgorithmId() {
        byte[] content = HexFormat.of().parseHex("2A864886F70D010101");
        String algorithmId = ASN1ObjectIdentifier.getAlgorithmId(content);
        assertEquals("RSA", algorithmId, "Algorithm ID mismatch");

        content = HexFormat.of().parseHex("2b6571");
        algorithmId = ASN1ObjectIdentifier.getAlgorithmId(content);
        assertEquals("EdDSA", algorithmId, "Algorithm ID mismatch");
    }
}