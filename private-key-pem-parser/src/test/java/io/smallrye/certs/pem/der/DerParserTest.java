package io.smallrye.certs.pem.der;

import io.vertx.core.buffer.Buffer;
import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

class DerParserTest {

    @Test
    void testIntegerParsing() {
        // ASN.1 DER encoding of an INTEGER with value 5
        byte[] bytes = new byte[] { 0x02, 0x01, 0x05 }; // TAG: 0x02 (INTEGER), LENGTH: 0x01, VALUE: 0x05
        DerParser parser = new DerParser(bytes);

        assertEquals(DerParser.Type.PRIMITIVE, parser.type());
        assertEquals(DerParser.Tag.INTEGER.number(), parser.tag());
        assertEquals(5, parser.content().getByte(0));
    }

    @Test
    void testOctetStringParsing() {
        // ASN.1 DER encoding of an OCTET STRING with value "AB"
        byte[] bytes = new byte[] { 0x04, 0x02, 0x41, 0x42 }; // TAG: 0x04 (OCTET STRING), LENGTH: 0x02, VALUE: "AB"
        DerParser parser = new DerParser(bytes);

        assertEquals(DerParser.Type.PRIMITIVE, parser.type());
        assertEquals(DerParser.Tag.OCTET_STRING.number(), parser.tag());
        assertEquals(2, parser.content().length());
        assertEquals((byte) 0x41, parser.content().getByte(0));
        assertEquals((byte) 0x42, parser.content().getByte(1));
    }

    @Test
    void testObjectIdentifierParsing() {
        // ASN.1 DER encoding of an OBJECT IDENTIFIER with value 1.2.840.113549
        byte[] bytes = new byte[] { 0x06, 0x06, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D };
        DerParser parser = new DerParser(bytes);

        assertEquals(DerParser.Type.PRIMITIVE, parser.type());
        assertEquals(DerParser.Tag.OBJECT_IDENTIFIER.number(), parser.tag());
        assertEquals(6, parser.content().length());
    }

    @Test
    void testSequenceParsing() {
        // ASN.1 DER encoding of a SEQUENCE containing an INTEGER (5) and BOOLEAN (true)
        byte[] bytes = new byte[] {
                0x10, 0x06, // SEQUENCE TAG (0x10) with LENGTH 6
                0x02, 0x01, 0x05, // INTEGER TAG (0x02) with LENGTH 1 and VALUE 5
                0x01, 0x01, (byte) 0xFF // BOOLEAN TAG (0x01) with LENGTH 1 and VALUE true (0xFF)
        };
        DerParser parser = new DerParser(bytes);

        assertEquals(DerParser.Type.PRIMITIVE, parser.type());
        assertEquals(DerParser.Tag.SEQUENCE.number(), parser.tag());
        assertEquals(6, parser.content().length());
    }

    @Test
    void testMultiByteLengthParsing() {
        // ASN.1 DER encoding of an OCTET STRING with a long length (256 bytes)
        byte[] bytes = new byte[260];
        bytes[0] = 0x04; // TAG for OCTET STRING
        bytes[1] = (byte) 0x82; // Length in two bytes (0x82 means multi-byte length follows)
        bytes[2] = 0x01; // High byte of length (256 bytes)
        bytes[3] = 0x00; // Low byte of length (256 bytes)

        DerParser parser = new DerParser(bytes);

        assertEquals(DerParser.Type.PRIMITIVE, parser.type());
        assertEquals(DerParser.Tag.OCTET_STRING.number(), parser.tag());
        assertEquals(256, parser.content().length());
    }

    @Test
    void testAsn1SequenceParsing() {
        // ASN.1 DER encoding of a SEQUENCE (0x30) containing:
        // - INTEGER (value: 10)
        // - OCTET STRING (value: "AB")
        byte[] bytes = new byte[] {
                0x30, 0x07, // SEQUENCE TAG (0x30) with LENGTH 7
                0x02, 0x01, 0x0A, // INTEGER TAG (0x02) with LENGTH 1 and VALUE 10
                0x04, 0x02, 0x41, 0x42 // OCTET STRING TAG (0x04) with LENGTH 2 and VALUE "AB"
        };

        DerParser parser = new DerParser(bytes);

        assertEquals(DerParser.Type.CONSTRUCTED, parser.type());
        assertEquals(0x10, parser.tag()); // SEQUENCE tag is 0x10 in the enum mapping
        assertEquals(7, parser.content().length());

        // Now verify the inner elements
        Buffer content = parser.content();

        // INTEGER element
        DerParser intParser = new DerParser(new byte[] { content.getByte(0), content.getByte(1), content.getByte(2) });
        assertEquals(DerParser.Type.PRIMITIVE, intParser.type());
        assertEquals(DerParser.Tag.INTEGER.number(), intParser.tag());
        assertEquals(1, intParser.content().length());
        assertEquals(10, intParser.content().getByte(0));

        // OCTET STRING element
        DerParser octetStringParser = new DerParser(
                new byte[] { content.getByte(3), content.getByte(4), content.getByte(5), content.getByte(6) });
        assertEquals(DerParser.Type.PRIMITIVE, octetStringParser.type());
        assertEquals(DerParser.Tag.OCTET_STRING.number(), octetStringParser.tag());
        assertEquals(2, octetStringParser.length());
        assertEquals(2, octetStringParser.content().length());
        assertEquals((byte) 0x41, octetStringParser.content().getByte(0));
        assertEquals((byte) 0x42, octetStringParser.content().getByte(1));
    }

    @Test
    void testAsn1SequenceParsingUsingNext() {
        // ASN.1 DER encoding of a SEQUENCE (0x30) containing:
        // - INTEGER (value: 10)
        // - OCTET STRING (value: "AB")
        byte[] bytes = new byte[] {
                0x30, 0x07, // SEQUENCE TAG (0x30) with LENGTH 7
                0x02, 0x01, 0x0A, // INTEGER TAG (0x02) with LENGTH 1 and VALUE 10
                0x04, 0x02, 0x41, 0x42 // OCTET STRING TAG (0x04) with LENGTH 2 and VALUE "AB"
        };

        DerParser parser = new DerParser(bytes);

        assertEquals(DerParser.Type.CONSTRUCTED, parser.type());
        assertEquals(0x10, parser.tag()); // SEQUENCE tag is 0x10 in the enum mapping
        assertEquals(7, parser.length());

        DerParser first = parser.next();
        DerParser second = parser.next();
        DerParser third = parser.next();

        // INTEGER element
        assertEquals(DerParser.Type.PRIMITIVE, first.type());
        assertEquals(DerParser.Tag.INTEGER.number(), first.tag());
        assertEquals(1, first.content().length());
        assertEquals(10, first.content().getByte(0));

        // OCTET STRING element
        assertEquals(DerParser.Type.PRIMITIVE, second.type());
        assertEquals(DerParser.Tag.OCTET_STRING.number(), second.tag());
        assertEquals(2, second.length());
        assertEquals(2, second.content().length());
        assertEquals((byte) 0x41, second.content().getByte(0));
        assertEquals((byte) 0x42, second.content().getByte(1));

        // No more elements
        assertNull(third);
        assertNull(parser.next());
        // Illegal calls
        assertNull(first.next());
        assertNull(second.next());
    }

    @Test
    void testIndefiniteFormError() {
        // Example of an invalid DER encoding (indefinite form is not supported in DER)
        byte[] bytes = new byte[] { 0x04, (byte) 0x80 }; // OCTET STRING with indefinite length form (0x80)

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            new DerParser(bytes);
        });
        assertTrue(exception.getMessage().contains("Indefinite form is not supported"));
    }

    @Test
    void testParseNestedDERSequence() {
        // Pre-constructed DER byte array representing the structure:
        // SEQUENCE (outer) -> SEQUENCE (inner) -> INTEGER (42)
        byte[] derData = {
                0x10, 0x05, // Outer SEQUENCE, length 5 bytes
                0x10, 0x03, // Inner SEQUENCE, length 4 bytes
                0x02, 0x01, 0x2A // INTEGER with value 42 (0x2A in hex)
        };

        // Initialize DER parser
        DerParser parser = new DerParser(derData);

        // Check that the first object is a sequence
        assertEquals(DerParser.Type.PRIMITIVE, parser.type());
        assertEquals(DerParser.Tag.SEQUENCE.number(), parser.tag());

        var innerSeq = parser.next();
        assertEquals(DerParser.Type.PRIMITIVE, innerSeq.type());
        assertEquals(DerParser.Tag.SEQUENCE.number(), innerSeq.tag());
        var num = innerSeq.next();
        assertEquals(DerParser.Type.PRIMITIVE, num.type());
        assertEquals(DerParser.Tag.INTEGER.number(), num.tag());
        assertEquals(42, num.content().getByte(0));
    }

    @Test
    void testParseNestedDERASN1Sequence() {
        // Pre-constructed DER byte array representing the structure:
        // SEQUENCE (outer) -> SEQUENCE (inner) -> INTEGER (42)
        byte[] derData = {
                0x30, 0x05, // Outer SEQUENCE, length 5 bytes
                0x30, 0x03, // Inner SEQUENCE, length 4 bytes
                0x02, 0x01, 0x2A // INTEGER with value 42 (0x2A in hex)
        };

        // Initialize DER parser
        DerParser parser = new DerParser(derData);

        // Check that the first object is a sequence
        assertEquals(DerParser.Type.CONSTRUCTED, parser.type());
        assertEquals(DerParser.Tag.SEQUENCE.number(), parser.tag());

        var innerSeq = parser.next();
        assertEquals(DerParser.Type.CONSTRUCTED, innerSeq.type());
        assertEquals(DerParser.Tag.SEQUENCE.number(), innerSeq.tag());
        var num = innerSeq.next();
        assertEquals(DerParser.Type.PRIMITIVE, num.type());
        assertEquals(DerParser.Tag.INTEGER.number(), num.tag());
        assertEquals(42, num.content().getByte(0));
    }
}
