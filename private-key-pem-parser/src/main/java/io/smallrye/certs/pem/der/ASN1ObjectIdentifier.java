package io.smallrye.certs.pem.der;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

/**
 * ANS.1 encoded object identifiers.
 */
public record ASN1ObjectIdentifier(byte[] value, String algorithmId) {

    /**
     * DSA (ANSI X9.57 algorithm)
     */
    static final ASN1ObjectIdentifier OID_1_2_840_10040_4_1 = ASN1ObjectIdentifier.from("2a8648ce380401", "DSA");
    /**
     * PKCS #1 (RSA Encryption)
     */
    public static final ASN1ObjectIdentifier OID_1_2_840_113549_1_1_1 = ASN1ObjectIdentifier.from("2A864886F70D010101", "RSA");

    /**
     * PKCS #1 (RSA PSS)
     */
    static final ASN1ObjectIdentifier OID_1_2_840_113549_1_1_10 = ASN1ObjectIdentifier.from("2a864886f70d01010a", "RSA");
    /**
     * ECDH 25519 key agreement algorithm (Curve X25519) - XDH
     */
    static final ASN1ObjectIdentifier OID_1_3_101_110 = ASN1ObjectIdentifier.from("2b656e", "XDH");

    /**
     * ECDH 448 key agreement algorithm (Curve X448) - XDH
     */
    static final ASN1ObjectIdentifier OID_1_3_101_111 = ASN1ObjectIdentifier.from("2b656f", "XDH");

    /**
     * EdDSA 25519 signature algorithm (Curve Ed25519)
     */
    static final ASN1ObjectIdentifier OID_1_3_101_112 = ASN1ObjectIdentifier.from("2b6570", "EdDSA");
    /**
     * EdDSA 448 signature algorithm (Curve Ed448)
     */
    static final ASN1ObjectIdentifier OID_1_3_101_113 = ASN1ObjectIdentifier.from("2b6571", "EdDSA");

    /**
     * ANSI X9.62 public key type (ecPublicKey)
     */
    static final ASN1ObjectIdentifier OID_1_2_840_10045_2_1 = ASN1ObjectIdentifier.from("2a8648ce3d0201", "EC");

    static final List<ASN1ObjectIdentifier> ALGORITHMS = List.of(
            OID_1_2_840_113549_1_1_1,
            OID_1_2_840_113549_1_1_10,
            OID_1_2_840_10040_4_1,
            OID_1_3_101_110,
            OID_1_3_101_111,
            OID_1_3_101_112,
            OID_1_3_101_113,
            OID_1_2_840_10045_2_1);

    /**
     * SECG (Certicom) named elliptic curve (secp384r1)
     */
    static final ASN1ObjectIdentifier OID_1_3_132_0_34 = ASN1ObjectIdentifier.from("2b81040022", "EC");

    public static ASN1ObjectIdentifier from(String hexString, String algorithmId) {
        return new ASN1ObjectIdentifier(HexFormat.of().parseHex(hexString), algorithmId);
    }

    public static String getAlgorithmId(byte[] content) {
        for (ASN1ObjectIdentifier oid : ALGORITHMS) {
            if (Arrays.equals(oid.value(), content)) {
                return oid.algorithmId();
            }
        }
        return null;
    }
}