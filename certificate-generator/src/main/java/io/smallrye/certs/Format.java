package io.smallrye.certs;

/**
 * The format of certificates.
 */
public enum Format {
    PEM,
    JKS,
    PKCS12;

    String extension() {
        return switch (this) {
            case PEM -> "pem";
            case JKS -> "jks";
            case PKCS12 -> "p12";
        };
    }
}
