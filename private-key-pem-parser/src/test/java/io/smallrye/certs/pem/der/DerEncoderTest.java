package io.smallrye.certs.pem.der;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

class DerEncoderTest {

    @Test
    void testIntegerEncoding() {
        DerEncoder encoder = new DerEncoder();
        encoder.integer(0x05); // INTEGER with value 5

        byte[] expected = new byte[] { 0x02, 0x01, 0x05 }; // INTEGER tag (0x02), length 1, value 5
        assertArrayEquals(expected, encoder.toBytes());
    }

    @Test
    void testOctetStringEncoding() {
        DerEncoder encoder = new DerEncoder();
        encoder.octetString(new byte[] { 0x41, 0x42 }); // OCTET STRING with value "AB"

        byte[] expected = new byte[] { 0x04, 0x02, 0x41, 0x42 }; // OCTET STRING tag (0x04), length 2, value "AB"
        assertArrayEquals(expected, encoder.toBytes());
    }

    @Test
    void testObjectIdEncoding() {
        DerEncoder encoder = new DerEncoder();
        encoder.oid(new ASN1ObjectIdentifier(new byte[] { 0x2A, (byte) 0x86, 0x48 }, "foo")); // OID representing 1.2.840
        byte[] expected = new byte[] { 0x06, 0x03, 0x2A, (byte) 0x86, 0x48 }; // OID tag (0x06), length 3, value 1.2.840
        assertArrayEquals(expected, encoder.toBytes());
    }

    @Test
    void testSequenceEncoding() {
        DerEncoder encoder = new DerEncoder();
        encoder.sequence(new byte[] { 0x02, 0x01, 0x0A, 0x04, 0x02, 0x41, 0x42 }); // SEQUENCE with INTEGER (10) and OCTET STRING ("AB")

        byte[] expected = new byte[] {
                0x30, 0x07, // SEQUENCE tag (0x30), length 7
                0x02, 0x01, 0x0A, // INTEGER (10)
                0x04, 0x02, 0x41, 0x42 // OCTET STRING ("AB")
        };
        assertArrayEquals(expected, encoder.toBytes());
    }

    @Test
    void testMultiByteLengthEncoding() {
        DerEncoder encoder = new DerEncoder();
        byte[] longContent = new byte[256]; // Content of 256 bytes for multi-byte length test
        encoder.octetString(longContent);

        byte[] result = encoder.toBytes();

        assertEquals(0x04, result[0]); // OCTET STRING tag
        assertEquals((byte) 0x82, result[1]); // Multi-byte length indicator (0x82 means next two bytes indicate length)
        assertEquals(0x01, result[2]); // Length high byte (256 in two bytes)
        assertEquals(0x00, result[3]); // Length low byte
        assertEquals(256, result.length - 4); // Content length
    }

    @Test
    void testSequenceContainingMultipleElements() {
        DerEncoder sequenceEncoder = new DerEncoder();
        DerEncoder intEncoder = new DerEncoder();
        DerEncoder stringEncoder = new DerEncoder();

        intEncoder.integer(0x05); // INTEGER with value 5
        stringEncoder.octetString(new byte[] { 0x41, 0x42 }); // OCTET STRING with value "AB"

        sequenceEncoder.sequence(intEncoder.toBytes());
        sequenceEncoder.addToSequence(stringEncoder.toBytes());

        byte[] sequence = sequenceEncoder.toBytes();

        assertEquals(0x30, sequence[0]); // ASN1 SEQUENCE tag
        assertEquals(2 + intEncoder.toBytes().length + stringEncoder.toBytes().length, sequence.length);
    }

    @Test
    void testEmptyOidEncoding() {
        DerEncoder encoder = new DerEncoder();
        encoder.oid(null); // NULL OID

        byte[] expected = new byte[] { 0x05, 0x00 }; // NULL tag (0x05), length 0
        assertArrayEquals(expected, encoder.toBytes());
    }

}
