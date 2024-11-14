package io.smallrye.certs.pem.der;

import io.vertx.core.buffer.Buffer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Simple ASN.1 DER encoder.
 * Inspired by <a href=
 * "https://github.com/AdoptOpenJDK/openjdk-jdk11/blob/master/src/java.base/share/classes/sun/security/util/DerOutputStream.java">DerOutputStream.java</a>.
 */
public class DerEncoder {

    private final Buffer payload = Buffer.buffer();

    public void oid(ASN1ObjectIdentifier oid) {
        int code = (oid != null) ? 0x06 : 0x05; // 5: NULL, 6: OID
        encode(code, (oid != null) ? oid.value() : null);
    }

    public void integer(int... encodedInteger) {
        encode(0x02, toBytes(encodedInteger));
    }

    public void octetString(byte[] bytes) {
        encode(0x04, bytes);
    }

    public void sequence(byte[] bytes) {
        // This is because in X.509 formats, the SEQUENCE type is used in constructed form.
        // As the result, 6th bit is set to 1. By setting 1 in 6th bit for SEQUENCE universal tag (0x10)
        // you get 0x30
        encode(0x30, bytes);
    }

    public void addToSequence(byte[] bytes) {
        payload.appendBytes(bytes);
    }

    private void write(int c) {
        payload.appendByte((byte) c);
    }

    private void encode(int code, byte[] bytes) {
        write(code);
        int length = (bytes != null) ? bytes.length : 0;
        if (length <= 127) {
            write(length & 0xFF);
        } else {
            ByteArrayOutputStream lengthStream = new ByteArrayOutputStream();
            while (length != 0) {
                lengthStream.write(length & 0xFF);
                length = length >> 8;
            }
            byte[] lengthBytes = lengthStream.toByteArray();
            write(0x80 | lengthBytes.length);
            for (int i = lengthBytes.length - 1; i >= 0; i--) {
                write(lengthBytes[i]);
            }
        }
        if (bytes != null) {
            payload.appendBytes(bytes);
        }
    }

    private static byte[] toBytes(int... elements) {
        if (elements == null) {
            return null;
        }
        byte[] result = new byte[elements.length];
        for (int i = 0; i < elements.length; i++) {
            result[i] = (byte) elements[i];
        }
        return result;
    }

    public byte[] toSequence() throws IOException {
        DerEncoder sequenceEncoder = new DerEncoder();
        sequenceEncoder.sequence(toBytes());
        return sequenceEncoder.toBytes();
    }

    public byte[] toBytes() {
        return payload.getBytes();
    }

    //    /**
    //     * Creates a sequence or appends a DER object to a sequence.
    //     *
    //     * @param bytes the bytes representing the object to add. It's important that the bytes are a value DER encoded value (tag | length | value)
    //     * @throws IOException if the write fails
    //     */
    //    public void sequence(byte[] bytes) throws IOException {
    //        // This is because in X.509 formats, the SEQUENCE type is used in constructed form.
    //        // As the result, 6th bit is set to 1. By setting 1 in 6th bit for SEQUENCE universal tag (0x10)
    //        // you get 0x30
    //        if (payload.length() == 0) {
    //            encode(0x30, bytes);
    //        } else {
    //            payload.appendBytes(bytes);
    //        }
    //    }

}