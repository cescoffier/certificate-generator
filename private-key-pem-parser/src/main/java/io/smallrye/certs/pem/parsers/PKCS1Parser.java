package io.smallrye.certs.pem.parsers;

import io.smallrye.certs.pem.der.DerEncoder;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parse PKCS1 private key (RSA) from PEM format.
 */
public class PKCS1Parser implements PKPemParser {

    private static final String PKCS1_RSA_START = "-+BEGIN\\s+RSA\\s+PRIVATE\\s+KEY[^-]*-+(?:\\s|\\r|\\n)+";

    private static final String PKCS1_RSA_END = "-+END\\s+RSA\\s+PRIVATE\\s+KEY[^-]*-+";

    private static final Pattern PKCS1_PATTERN = Pattern.compile(PKCS1_RSA_START + BASE64_TEXT + PKCS1_RSA_END,
            Pattern.CASE_INSENSITIVE);

    @Override
    public PrivateKey getKey(String content, String ignored) {
        try {
            Matcher matcher = PKCS1_PATTERN.matcher(content);
            if (matcher.find()) {
                var encoded = matcher.group(BASE64_TEXT_GROUP);
                var decoded = decodeBase64(encoded);
                return extract(decoded);
            }
        } catch (Exception e) {
            return null;
        }
        // Does not match PKCS1 pattern
        return null;
    }

    private PrivateKey extract(byte[] decoded) {
        try {
            DerEncoder encoder = new DerEncoder();
            encoder.integer(0x00); // Version 0

            DerEncoder algorithmIdentifier = new DerEncoder();
            algorithmIdentifier.oid(RSA_ALGORITHM);
            algorithmIdentifier.oid(null);

            encoder.sequence(algorithmIdentifier.toBytes());
            encoder.octetString(decoded);
            var spec = new PKCS8EncodedKeySpec(encoder.toSequence());
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

}
