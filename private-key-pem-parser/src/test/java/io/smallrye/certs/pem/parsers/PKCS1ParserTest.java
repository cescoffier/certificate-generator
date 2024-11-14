package io.smallrye.certs.pem.parsers;

import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PKCS1ParserTest {

    private PKCS1Parser parser;
    private String key;
    private PrivateKey originalPrivateKey;

    @BeforeEach
    void setup() throws NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeySpecException {
        Security.addProvider(new BouncyCastleProvider());

        // Step 1: Generate RSA Key Pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        originalPrivateKey = keyPair.getPrivate();

        // Step 2: Extract the key parameters from the private key
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPrivateCrtKeySpec privateKeySpec = keyFactory.getKeySpec(originalPrivateKey, RSAPrivateCrtKeySpec.class);

        // Step 3: Construct PKCS#1 format using RSAPrivateKey structure
        RSAPrivateKey pkcs1PrivateKey = new RSAPrivateKey(
                privateKeySpec.getModulus(),
                privateKeySpec.getPublicExponent(),
                privateKeySpec.getPrivateExponent(),
                privateKeySpec.getPrimeP(),
                privateKeySpec.getPrimeQ(),
                privateKeySpec.getPrimeExponentP(),
                privateKeySpec.getPrimeExponentQ(),
                privateKeySpec.getCrtCoefficient());

        // Step 4: Convert the RSAPrivateKey ASN.1 object to DER-encoded bytes
        byte[] pkcs1Bytes = pkcs1PrivateKey.getEncoded();

        // Step 5: Encode as PEM using PemWriter
        StringWriter stringWriter = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(stringWriter)) {
            pemWriter.writeObject(new PemObject("RSA PRIVATE KEY", pkcs1Bytes));
        }

        key = stringWriter.toString();
        parser = new PKCS1Parser();
    }

    @Test
    void testParseValidPkcs1Key() {
        PrivateKey pk = parser.getKey(key, null);
        assertNotNull(pk, "Parsed private key should not be null for valid PKCS1 key");

        // Verify the decoded key length or check against a known portion of the DER-encoded output
        byte[] keyBytes = pk.getEncoded();
        assertTrue(keyBytes.length > 0, "Encoded key bytes should not be empty");

        // Check the initial bytes for ASN.1 sequence (SEQUENCE tag, length, etc.) for PKCS8 format
        assertEquals(0x30, keyBytes[0] & 0xFF,
                "Key should start with SEQUENCE tag (0x30 in DER)");
    }

    @Test
    void testParseInvalidPkcs1KeyFormat() {
        String invalidKey = """
                -----BEGIN RSA PRIVATE KEY-----
                InvalidBase64Data==
                -----END RSA PRIVATE KEY-----
                """;
        PrivateKey pk = parser.getKey(invalidKey, null);
        assertNull(pk, "Parsed private key should be null for invalid PKCS1 key format");
    }

    @Test
    void testParseNonMatchingKey() {
        String nonMatchingKey = """
                -----BEGIN PUBLIC KEY-----
                MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsdklj+ksdLq93Q==
                -----END PUBLIC KEY-----
                """;
        PrivateKey pk = parser.getKey(nonMatchingKey, null);
        assertNull(pk, "Parsed PKCS8EncodedKeySpec should be null for non-matching key format");
    }

    @Test
    void testParseCorruptedPkcs1KeyData() {
        String corruptedKey = """
                -----BEGIN RSA PRIVATE KEY-----
                MIIBOgIBAAJBAK5Erl8asdk==  // corrupted base64 data
                -----END RSA PRIVATE KEY-----
                """;
        PrivateKey pk = parser.getKey(corruptedKey, null);
        assertNull(pk, "Parsed private key should be null for corrupted PKCS1 key data");
    }

    @Test
    void testParsePkcs1KeyWithExcessiveWhitespace() {
        String keyWithWhitespace = """
                -----BEGIN RSA PRIVATE KEY-----

                MIIBOgIBAAJBAK5Erl8a+lFsA8MPsh9aL9F+NfgmHNkGr/H0X0KdD/YU==

                -----END RSA PRIVATE KEY-----
                """;
        PrivateKey pk = parser.getKey(keyWithWhitespace, null);
        assertNull(pk, "Parsed private key should be null for PKCS1 key with excessive whitespace");
    }

    @Test
    void testParseNonRsaPrivateKey() {
        String nonRsaKey = """
                -----BEGIN PRIVATE KEY-----
                MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZC5aj6qwMF0l4V9+
                E/Ns9js0Jx/vCEyXOg9T/MSTwRKhRANCAASFiBQ7XOkEHVFhzdL//o7aEdDmd0I5
                KUYl3ofGdhduE5F3YoxftD0YrPrk73dbmZZKqzHpD6nG7T8PzYpGpB4L
                -----END PRIVATE KEY-----
                """;
        PrivateKey pk = parser.getKey(nonRsaKey, null);
        assertNull(pk, "Parsed private key should be null for non-RSA private key data");
    }

    @Test
    void testParsePkcs1KeyWithIncorrectHeaderOrder() {
        String invalidHeaderOrderKey = """
                -----END RSA PRIVATE KEY-----
                MIIBOgIBAAJBAK5Erl8a+lFsA8MPsh9aL9F+NfgmHNkGr/H0X0KdD/YU==
                -----BEGIN RSA PRIVATE KEY-----
                """;
        PrivateKey pk = parser.getKey(invalidHeaderOrderKey, null);
        assertNull(pk, "Parsed private key should be null for PKCS1 key with incorrect header order");
    }

    @Test
    void testParseUnsupportedAlgorithm() {
        String dsaPrivateKey = """
                -----BEGIN DSA PRIVATE KEY-----
                MIIBugIBAAKBgQDGRn7MQjFl+hLehRihs14kn5PHKeMThCbxwU82Wl5uCk6JX/YK
                K+dzpf8ZkVPoMc1kZyMCUVYmj4nnIqbi7dBnL/NL9ixv9A5OwOwRVFYmXwvfr9dK
                -----END DSA PRIVATE KEY-----
                """;
        PrivateKey pk = parser.getKey(dsaPrivateKey, null);
        assertNull(pk, "Parsed private key should be null for unsupported algorithm");
    }

    @Test
    void testParsePkcs1KeyWithExtraDataAroundPemHeaders() {
        String keyWithExtraData = """
                Some extra data before the key
                -----BEGIN RSA PRIVATE KEY-----
                MIIBOgIBAAJBAK5Erl8a+lFsA8MPsh9aL9F+NfgmHNkGr/H0X0KdD/YU==
                -----END RSA PRIVATE KEY-----
                Some extra data after the key
                """;
        PrivateKey pk = parser.getKey(keyWithExtraData, null);
        assertNull(pk, "Parsed private key should be null even with extra data around the PEM headers");
    }

    @Test
    void testParseUnsupportedKeySize() {
        String smallKey = """
                -----BEGIN RSA PRIVATE KEY-----
                MIIBAgIBAAIBAAIBAA==
                -----END RSA PRIVATE KEY-----
                """;
        PrivateKey pk = parser.getKey(smallKey, null);
        assertNull(pk, "Parsed private key should be null for unsupported key size");
    }

    @Test
    void testParsePkcs1KeyMatchesOriginal() throws Exception {
        // Parse the PEM-encoded key
        PrivateKey parsedPrivateKey = parser.getKey(key, null);
        assertNotNull(parsedPrivateKey, "Parsed private key should not be null for valid PKCS1 key");

        // Check if parsed private key matches original private key's properties
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPrivateCrtKeySpec originalSpec = keyFactory.getKeySpec(originalPrivateKey, RSAPrivateCrtKeySpec.class);
        RSAPrivateCrtKeySpec parsedSpec = keyFactory.getKeySpec(parsedPrivateKey, RSAPrivateCrtKeySpec.class);

        // Compare essential RSA parameters
        assertEquals(originalSpec.getModulus(), parsedSpec.getModulus(), "Modulus should match");
        assertEquals(originalSpec.getPrivateExponent(), parsedSpec.getPrivateExponent(), "Private exponent should match");
        assertEquals(originalSpec.getPublicExponent(), parsedSpec.getPublicExponent(), "Public exponent should match");
        assertEquals(originalSpec.getPrimeP(), parsedSpec.getPrimeP(), "Prime P should match");
        assertEquals(originalSpec.getPrimeQ(), parsedSpec.getPrimeQ(), "Prime Q should match");
        assertEquals(originalSpec.getPrimeExponentP(), parsedSpec.getPrimeExponentP(), "Prime Exponent P should match");
        assertEquals(originalSpec.getPrimeExponentQ(), parsedSpec.getPrimeExponentQ(), "Prime Exponent Q should match");
        assertEquals(originalSpec.getCrtCoefficient(), parsedSpec.getCrtCoefficient(), "CRT Coefficient should match");
    }
}