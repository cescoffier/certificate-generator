package io.smallrye.certs.pem.der;

import io.vertx.core.buffer.Buffer;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * An ASN.1 DER encoded element.
 * <p>
 * The ASN.1 DER encoding is a standard way to encode data structures in binary form:
 * {@code Identifier octets type | Length octets |	Contents octets (Value) | End-of-Contents octets (only if indefinite form)}
 *
 * @see <a href="https://en.wikipedia.org/wiki/X.690">Wikipedia page</a>
 */
public class DerParser {

    // See https://en.wikipedia.org/wiki/X.690#Encoding
    public enum Type {
        PRIMITIVE,
        CONSTRUCTED;

        static Type from(byte b) {
            return ((b & 0x20) == 0) ? PRIMITIVE : CONSTRUCTED;
        }

    }

    // See https://en.wikipedia.org/wiki/X.690#Identifier_octets.
    public enum Tag {
        // Usual Tag, attention to the ASN Sequence using 0x30 and not 0x10 because it's a constructed type.
        INTEGER(0x02),
        OCTET_STRING(0x04),
        OBJECT_IDENTIFIER(0x06),
        SEQUENCE(0x10),
        ASN1_SEQUENCE(0x30);

        private final int number;

        Tag(int n) {
            number = n;
        }

        public int number() {
            return number;
        }
    }

    /**
     * The type of the element (primitive or constructed).
     */
    private final Type type;

    /**
     * The tag of the element (decimal value).
     */
    private final long tag;

    /**
     * The length of the content.
     * Be aware this is not the size of the byte array.
     */
    private final int length;

    /**
     * The content of the element.
     */
    private final Buffer content;

    /**
     * The size of the element (tag + length + content).
     */
    private final int size;

    /**
     * The position in the content.
     * Used to iterate over the content (sequence).
     */
    private int cursor;

    public DerParser(byte[] bytes) {
        var position = new AtomicInteger(0);
        var buffer = Buffer.buffer(bytes);
        byte b = buffer.getByte(position.getAndIncrement());
        type = Type.from(b);
        tag = decodeTag(b, buffer, position);
        length = decodeLength(buffer, position);
        content = buffer.slice(position.get(), position.get() + length);
        size = position.get() + length;
        cursor = 0; // Position in the content
    }

    private long decodeTag(byte b, Buffer bytes, AtomicInteger position) {
        // See https://en.wikipedia.org/wiki/X.690#Identifier_octets
        long t = (b & 0x1F);
        if (t != 0x1F) {
            return t;
        }
        t = 0;
        b = bytes.getByte(position.getAndIncrement());
        while ((b & 0x80) != 0) {
            t <<= 7;
            t = t | (b & 0x7F);
            b = bytes.getByte(position.getAndIncrement());
        }
        return t;
    }

    private int decodeLength(Buffer bytes, AtomicInteger position) {
        byte b = bytes.getByte(position.getAndIncrement());
        if ((b & 0x80) == 0) {
            return b & 0x7F;
        }
        int numberOfLengthBytes = (b & 0x7F);
        if (numberOfLengthBytes == 0) {
            throw new IllegalArgumentException("Indefinite form is not supported");
        }
        int length = 0;
        for (int i = 0; i < numberOfLengthBytes; i++) {
            length <<= 8;
            length |= (bytes.getByte(position.getAndIncrement()) & 0xFF);
        }
        return length;
    }

    public Buffer content() {
        return this.content;
    }

    public byte[] toByteArray() {
        return this.content.getBytes();
    }

    public Type type() {
        return type;
    }

    public long tag() {
        return tag;
    }

    public int length() {
        return length;
    }

    public DerParser next() {
        if (tag == Tag.ASN1_SEQUENCE.number() || tag == Tag.SEQUENCE.number()) {
            if (cursor < length) {
                var nested = new DerParser(content.getBytes(cursor, length));
                cursor = cursor + nested.size;
                return nested;
            }
        }
        return null;
    }

}