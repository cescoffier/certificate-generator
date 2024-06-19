package me.escoffier.certs.ca;

import me.escoffier.certs.CertificateGenerator;
import me.escoffier.certs.CertificateRequest;
import me.escoffier.certs.CertificateUtils;
import me.escoffier.certs.Format;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Generate a CA certificate (without the installation) and generate a signed certificate.
 */
public class GenerateCaTest {

    @Test
    void test() throws Exception {
        File out = new File("target/ca");
        out.mkdirs();

        var ca = new File(out, "ca.crt");
        var key = new File(out, "ca.key");
        var store = new File(out, "ks.p12");
        CaGenerator generator = new CaGenerator(ca, key, store, "test");
        generator.generate("localhost", "Test", "Test Dev", "home", "world", "Cloud");

        assertThat(ca).exists();
        assertThat(key).exists();
        assertThat(store).exists();

        File trustStore = new File(out, "truststore.p12");
        generator.generateTrustStore(trustStore);
        assertThat(trustStore).exists();


        // Generate a signed certificate
        CertificateGenerator gen = new CertificateGenerator(out.toPath(), true);
        gen.generate(new CertificateRequest().withName("test").signedWith(loadRootCertificate(ca), loadPrivateKey(key)).withFormat(Format.PKCS12).withPassword("secret"));

        File signedKS = new File(out, "test-keystore.p12");
        File signedTS = new File(out, "test-truststore.p12");

        assertThat(signedKS).exists();
        assertThat(signedTS).exists();

        try (FileInputStream fis = new FileInputStream(signedKS)) {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(fis, "secret".toCharArray());
            assertThat(ks.getCertificate("test")).isNotNull();
            assertThat(ks.getKey("test", "secret".toCharArray())).isNotNull();

            ks.getCertificate("test").verify(loadRootCertificate(ca).getPublicKey());
        }

        try (FileInputStream fis = new FileInputStream(signedTS)) {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(fis, "secret".toCharArray());
            assertThat(ks.getCertificate("test")).isNotNull();
        }

    }

    private X509Certificate loadRootCertificate(File ca) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (FileInputStream fis = new FileInputStream(ca)) {
            return (X509Certificate) cf.generateCertificate(fis);
        }
    }

    private PrivateKey loadPrivateKey(File key) throws Exception {
        try (BufferedReader reader = new BufferedReader(new FileReader(key));
             PEMParser pemParser = new PEMParser(reader)) {
            Object obj = pemParser.readObject();
            if (obj instanceof KeyPair) {
                return ((KeyPair) obj).getPrivate();
            } else if (obj instanceof PrivateKeyInfo) {
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
                return converter.getPrivateKey(((PrivateKeyInfo) obj));
            } else {
                throw new IllegalStateException(
                        "The file " + key.getAbsolutePath() + " does not contain a private key "
                                + obj.getClass().getName());
            }
        }
    }
}
