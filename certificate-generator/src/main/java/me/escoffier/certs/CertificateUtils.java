package me.escoffier.certs;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
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

    public static X509Certificate generateCertificate(KeyPair keyPair, String cn, List<String> sans, Duration duration) throws Exception {
        // Generate self-signed X509 Certificate
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        certGen.setSerialNumber(BigInteger.valueOf(System.nanoTime()));
        certGen.setSubjectDN(new X509Principal("CN=" + cn));
        certGen.setIssuerDN(new X509Principal("CN=" + cn));


        certGen.addExtension(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic()));
        certGen.addExtension(Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(keyPair.getPublic()));

        // Set certificate extensions
        // (1) digitalSignature extension
        certGen.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.keyAgreement | KeyUsage.nonRepudiation));

        certGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));

        // (2) extendedKeyUsage extension
        certGen.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth}));

        // (3) subjectAlternativeName
        if (sans.isEmpty()) {
            DERSequence subjectAlternativeNames = new DERSequence(new ASN1Encodable[]{
                    new GeneralName(GeneralName.dNSName, cn),
                    new GeneralName(GeneralName.iPAddress, "127.0.0.1"),
                    new GeneralName(GeneralName.iPAddress, "0.0.0.0")
            });
            certGen.addExtension(Extension.subjectAlternativeName, false, subjectAlternativeNames);
        } else {
            DERSequence subjectAlternativeNames =
                    new DERSequence(sans.stream().map(s -> {
                        if (s.startsWith("DNS:")) {
                            return new GeneralName(GeneralName.dNSName, s.substring(4));
                        } else if (s.startsWith("IP:")) {
                            return new GeneralName(GeneralName.iPAddress, s.substring(3));
                        } else {
                            return new GeneralName(GeneralName.dNSName, s);
                        }
                    }).toArray(ASN1Encodable[]::new));
            certGen.addExtension(Extension.subjectAlternativeName, false, subjectAlternativeNames);
        }


        var before = Instant.now().minus(2, ChronoUnit.DAYS);
        var after = Instant.now().plus(duration.toDays(), ChronoUnit.DAYS);

        certGen.setNotBefore(new java.util.Date(before.toEpochMilli()));
        certGen.setNotAfter(new java.util.Date(after.toEpochMilli()));
        certGen.setPublicKey(keyPair.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

        return certGen.generate(keyPair.getPrivate());
    }

    public static void writeCertificateToPEM(X509Certificate certificate, File output) throws IOException, CertificateEncodingException {
        try (FileWriter fileWriter = new FileWriter(output);
             BufferedWriter pemWriter = new BufferedWriter(fileWriter)) {
            pemWriter.write("-----BEGIN CERTIFICATE-----\n");
            pemWriter.write(Base64.getEncoder().encodeToString(certificate.getEncoded()));
            pemWriter.write("\n-----END CERTIFICATE-----\n\n");
        }
    }

    public static void writePrivateKeyToPem(PrivateKey privateKey, File output) throws Exception {
        try (FileWriter fileWriter = new FileWriter(output);
             BufferedWriter pemWriter = new BufferedWriter(fileWriter)) {
            pemWriter.write("-----BEGIN PRIVATE KEY-----\n");
            pemWriter.write(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
            pemWriter.write("\n-----END PRIVATE KEY-----\n\n");
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

    public static void writePrivateKeyAndCertificateToJKS(Map<String, CertificateHolder> certs, String password, File output) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);

        for (Map.Entry<String, CertificateHolder> entry : certs.entrySet()) {
            String alias = entry.getKey();
            keyStore.setKeyEntry(
                    alias,
                    entry.getValue().keys().getPrivate(),
                    entry.getValue().password(),
                    new Certificate[]{entry.getValue().certificate()});
        }

        FileOutputStream keyStoreFos = new FileOutputStream(output);
        keyStore.store(keyStoreFos, password.toCharArray());
        keyStoreFos.close();
    }

    public static void writeTrustStoreToJKS(Map<String, CertificateHolder> certificates, File output, char[] password) throws Exception {
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(null, null);
        for (Map.Entry<String, CertificateHolder> entry : certificates.entrySet()) {
            trustStore.setCertificateEntry(entry.getKey(), entry.getValue().certificate());
        }
        FileOutputStream trustStoreFos = new FileOutputStream(output);
        trustStore.store(trustStoreFos, password);
        trustStoreFos.close();
    }

    public static void writePrivateKeyAndCertificateToPKCS12(Map<String, CertificateHolder> certificates, File output, char[] password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);

        for (Map.Entry<String, CertificateHolder> entry : certificates.entrySet()) {
            keyStore.setKeyEntry(
                    entry.getKey(),
                    entry.getValue().keys().getPrivate(),
                    entry.getValue().password(),
                    new Certificate[]{entry.getValue().certificate()});
        }

        FileOutputStream keyStoreFos = new FileOutputStream(output);
        keyStore.store(keyStoreFos, password);
        keyStoreFos.close();
    }

    public static void writeTrustStoreToPKCS12(Map<String, CertificateHolder> certificates, File output, char[] password) throws Exception {
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        for (Map.Entry<String, CertificateHolder> entry : certificates.entrySet()) {
            trustStore.setCertificateEntry(entry.getKey(), entry.getValue().certificate());
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
        } else if (certificateFile.getName().endsWith(".pem") || certificateFile.getName().endsWith(".crt")) {
            try (BufferedReader reader = new BufferedReader(new FileReader(certificateFile));
                 PEMParser pemParser = new PEMParser(reader)) {
                Object obj = pemParser.readObject();
                if (obj instanceof X509Certificate) {
                    return (X509Certificate) obj;
                } if (obj instanceof X509CertificateHolder) {
                    return  new JcaX509CertificateConverter().getCertificate((X509CertificateHolder) obj);
                } else {
                    throw new IllegalArgumentException("Invalid PEM file format: " + obj);
                }
            }
        } else {
            throw new IllegalArgumentException("Unsupported certificate format. Only DER and PEM/CRT are supported.");
        }
    }
}