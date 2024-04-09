package me.escoffier.certs;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;

/**
 * A holder for a key pair and a certificate.
 */
public class CertificateHolder {

    private final KeyPair keys;
    private final X509Certificate certificate;

    private final KeyPair clientKeys;
    private final X509Certificate clientCertificate;

    private final String password;

    /**
     * Generates a new instance of {@link CertificateHolder}, with a new random key pair and a certificate.
     */
    public CertificateHolder(String cn, List<String> sans, Duration duration, boolean generateClient, String password) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        keys = keyPairGenerator.generateKeyPair();
        certificate = CertificateUtils.generateCertificate(keys, cn, sans, duration);

        if (generateClient) {
            clientKeys = keyPairGenerator.generateKeyPair();
            clientCertificate = CertificateUtils.generateCertificate(clientKeys, cn, sans, duration);
        } else {
            clientKeys = null;
            clientCertificate = null;
        }
        this.password = password;
    }

    public KeyPair keys() {
        return keys;
    }

    public X509Certificate certificate() {
        return certificate;
    }

    public KeyPair clientKeys() {
        return clientKeys;
    }

    public X509Certificate clientCertificate() {
        return clientCertificate;
    }

    public boolean hasClient() {
        return clientKeys != null;
    }

    public char[] password() {
        if (password == null) {
            return null;
        }
        return password.toCharArray();
    }
}
