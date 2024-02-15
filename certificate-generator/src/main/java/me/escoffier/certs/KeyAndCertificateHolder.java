package me.escoffier.certs;

import java.io.File;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.time.Duration;

/**
 * A holder for a key pair and a certificate.
 */
public class KeyAndCertificateHolder {


    private final KeyPair keys;
    private final X509Certificate certificate;

    /**
     * Generates a new instance of {@link KeyAndCertificateHolder}, with a new random key pair and a certificate.
     */
    public KeyAndCertificateHolder(String cn, Duration duration) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        keys = keyPairGenerator.generateKeyPair();
        certificate = CertificateUtils.generateCertificate(keys, cn, duration);
    }

    public KeyAndCertificateHolder(File privateKey, File certificate) throws Exception {
        this.keys = CertificateUtils.loadPrivateKey(privateKey);
        this.certificate = CertificateUtils.loadCertificate(certificate);
    }

    public KeyPair keys() {
        return keys;
    }

    public X509Certificate certificate() {
        return certificate;
    }
}
