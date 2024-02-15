package me.escoffier.certs;

import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Map;

class CertificateUtils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static X509Certificate generateCertificate(KeyPair keyPair, String cn, Duration duration) throws Exception {
        // Generate self-signed X509 Certificate
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        certGen.setSerialNumber(BigInteger.valueOf(System.nanoTime()));
        certGen.setSubjectDN(new X509Principal("CN=" + cn));
        certGen.setIssuerDN(new X509Principal("CN=" + cn));

        var before = Instant.now().minus(2, ChronoUnit.DAYS);
        var after = Instant.now().plus(duration.toDays(), ChronoUnit.DAYS);

        certGen.setNotBefore(new java.util.Date(before.toEpochMilli()));
        certGen.setNotAfter(new java.util.Date(after.toEpochMilli()));
        certGen.setPublicKey(keyPair.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

        return certGen.generate(keyPair.getPrivate());
    }

    public static void writePrivateKeyToPEM(PrivateKey privateKey, File output) throws IOException {
        PemObject pemObject = new PemObject("PRIVATE KEY", privateKey.getEncoded());
        try (FileWriter fileWriter = new FileWriter(output);
             PemWriter pemWriter = new PemWriter(fileWriter)) {
            pemWriter.writeObject(pemObject);
        }
    }

    public static void writePublicKeyToPEM(PublicKey publicKey, File output) throws IOException {
        PemObject pemObject = new PemObject("PUBLIC KEY", publicKey.getEncoded());
        try (FileWriter fileWriter = new FileWriter(output);
             PemWriter pemWriter = new PemWriter(fileWriter)) {
            pemWriter.writeObject(pemObject);
        }
    }

    public static void writeCertificateToDER(X509Certificate certificate, File output)
            throws IOException, CertificateEncodingException {
        byte[] derEncoded = certificate.getEncoded();
        try (FileOutputStream fos = new FileOutputStream(output)) {
            fos.write(derEncoded);
        }
    }

    public static void writeCertificateToPEM(X509Certificate certificate, File output) throws IOException, CertificateEncodingException {
        PemObject pemObject = new PemObject("CERTIFICATE", certificate.getEncoded());
        try (FileWriter writer = new FileWriter(output); PemWriter pemWriter = new PemWriter(writer)) {
            pemWriter.writeObject(pemObject);
        }
    }

    public static void writePrivateKeyToPem(PrivateKey privateKey, File output) throws Exception {
        try (FileWriter fileWriter = new FileWriter(output);
             JcaPEMWriter pemWriter = new JcaPEMWriter(fileWriter)) {
            pemWriter.writeObject(privateKey);
        }
    }

    public static void writeTruststoreToPem(List<X509Certificate> trustedCertificates, File output) throws Exception {
        try (FileWriter fileWriter = new FileWriter(output);
             BufferedWriter bufferedWriter = new BufferedWriter(fileWriter)) {
            // Write trusted certificates to truststore file
            for (X509Certificate certificate : trustedCertificates) {
                bufferedWriter.write("-----BEGIN CERTIFICATE-----\n");
                bufferedWriter.write(Base64.getEncoder().encodeToString(certificate.getEncoded()));
                bufferedWriter.write("\n-----END CERTIFICATE-----\n\n");
            }
        }
    }

    public static void writePrivateKeyAndCertificateToJKS(X509Certificate certificate, KeyPair keyPair, File output, char[] password, String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);
        keyStore.setKeyEntry(alias, keyPair.getPrivate(), password, new Certificate[]{certificate});
        FileOutputStream keyStoreFos = new FileOutputStream(output);
        keyStore.store(keyStoreFos, password);
        keyStoreFos.close();
    }

    public static void writeTrustStoreToJKS(Map<String, X509Certificate> certificates, File output, char[] password) throws Exception {
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(null, null);
        for (Map.Entry<String, X509Certificate> entry : certificates.entrySet()) {
            trustStore.setCertificateEntry(entry.getKey(), entry.getValue());
        }
        FileOutputStream trustStoreFos = new FileOutputStream(output);
        trustStore.store(trustStoreFos, password);
        trustStoreFos.close();
    }

    public static void writePrivateKeyAndCertificateToPKCS12(X509Certificate certificate, KeyPair keyPair, File output, char[] password, String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry(alias, keyPair.getPrivate(), password, new Certificate[]{certificate});
        FileOutputStream keyStoreFos = new FileOutputStream(output);
        keyStore.store(keyStoreFos, password);
        keyStoreFos.close();
    }

    public static void writeTrustStoreToPKCS12(Map<String, X509Certificate> certificates, File output, char[] password) throws Exception {
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        for (Map.Entry<String, X509Certificate> entry : certificates.entrySet()) {
            trustStore.setCertificateEntry(entry.getKey(), entry.getValue());
        }
        FileOutputStream trustStoreFos = new FileOutputStream(output);
        trustStore.store(trustStoreFos, password);
        trustStoreFos.close();
    }

    public static KeyPair loadPrivateKey(File keyFile) throws Exception {
        try (BufferedReader reader = new BufferedReader(new FileReader(keyFile));
             PEMParser pemParser = new PEMParser(reader)) {
            Object obj = pemParser.readObject();
            if (obj instanceof KeyPair) {
                return (KeyPair) obj;
            } else {
                throw new IllegalArgumentException("Invalid PEM file format");
            }
        }
    }

    public static X509Certificate loadCertificate(File certificateFile) throws Exception {
        if (certificateFile.getName().endsWith(".der")) {
            try (FileInputStream fis = new FileInputStream(certificateFile)) {
                var bytes = fis.readAllBytes();
                // Create a CertificateFactory and parse the DER-encoded bytes into an X509Certificate
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(bytes));
            }
        } else if (certificateFile.getName().endsWith(".pem")) {
            try (BufferedReader reader = new BufferedReader(new FileReader(certificateFile));
                 PEMParser pemParser = new PEMParser(reader)) {
                Object obj = pemParser.readObject();
                if (obj instanceof X509Certificate) {
                    return (X509Certificate) obj;
                } else {
                    throw new IllegalArgumentException("Invalid PEM file format");
                }
            }
        } else {
            throw new IllegalArgumentException("Unsupported certificate format. Only DER and PEM are supported.");
        }
    }
}