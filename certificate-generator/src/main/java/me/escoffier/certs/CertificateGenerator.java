package me.escoffier.certs;

import java.io.File;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import static me.escoffier.certs.CertificateUtils.*;

public class CertificateGenerator {

    final File root;

    static System.Logger LOGGER = System.getLogger(CertificateGenerator.class.getName());

    public CertificateGenerator(Path tempDir) {
        root = tempDir.toFile();
    }

    public CertificateGenerator() {
        root = new File(".");
    }

    public void generate(CertificateRequest request) throws Exception {
        request.validate();
        try {
            KeyAndCertificateHolder server = new KeyAndCertificateHolder(request.getCN(), request.getDuration());
            KeyPair keyPair = server.keys();
            X509Certificate certificate = server.certificate();

            KeyAndCertificateHolder client = null;
            KeyPair clientKeyPair = server.keys();
            X509Certificate clientCertificate = server.certificate();
            if (request.client()) {
                client = new KeyAndCertificateHolder(request.getCN(), request.getDuration());
                clientKeyPair = server.keys();
                clientCertificate = server.certificate();
            }

            for (Format format : request.formats()) {
                if (format == Format.PEM) {
                    File certFile = new File(root, request.name() + ".crt");
                    File keyFile = new File(root, request.name() + ".key");
                    File trustfile = new File(root, request.name() + (client!=null ? "-client" : "") + "-ca.crt");
                    File clientCertFile = new File(root, request.name() + "-client.crt");
                    File clientKeyFile = new File(root, request.name() + "-client.key");
                    File serverTrustfile = new File(root, request.name() + "-server-ca.crt");

                    writeCertificateToPEM(certificate, certFile);
                    writePrivateKeyToPem(keyPair.getPrivate(), keyFile);
                    writeTruststoreToPem(List.of(certificate), trustfile);

                    if (client != null) {
                        writeCertificateToPEM(clientCertificate, clientCertFile);
                        writePrivateKeyToPem(clientKeyPair.getPrivate(), clientKeyFile);
                        writeTruststoreToPem(List.of(clientCertificate), serverTrustfile);
                    }

                    LOGGER.log(System.Logger.Level.INFO, "⭐ PEM Certificates, keystore, and truststore generated successfully!");
                    LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD11  Key File: " + keyFile.getAbsolutePath());
                    LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDCDC  Cert File: " + certFile.getAbsolutePath());
                    if (client != null) {
                        LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD13  Server Trust Store File: " + serverTrustfile.getAbsolutePath());
                        LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD11  Client Key File: " + clientKeyFile.getAbsolutePath());
                        LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDCDC  Client Cert File: " + clientCertFile.getAbsolutePath());
                        LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD13  Client Trust Store File: " + trustfile.getAbsolutePath());
                    } else {
                        LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD13  Trust Store File: " + trustfile.getAbsolutePath());
                    }

                } else if (format == Format.JKS) {
                    File keyStoreFile = new File(root,  request.name() + "-keystore." + format.extension());
                    File trustStoreFile = new File(root, request.name() + (client!=null ? "-client" : "") + "-truststore." + format.extension());

                    File clientKeyStoreFile = new File(root,  request.name() + "-client-keystore." + format.extension());
                    File serverTrustStoreFile = new File(root,  request.name() + "-server-truststore." + format.extension());

                    writePrivateKeyAndCertificateToJKS(certificate, keyPair, keyStoreFile, request.password().toCharArray(), request.getAlias());
                    writeTrustStoreToJKS(Map.of(request.getAlias(), certificate), trustStoreFile, request.password().toCharArray());

                    if (client != null) {
                        writePrivateKeyAndCertificateToJKS(clientCertificate, clientKeyPair, clientKeyStoreFile, request.password().toCharArray(), request.getAlias());
                        writeTrustStoreToJKS(Map.of(request.getAlias(), clientCertificate), serverTrustStoreFile, request.password().toCharArray());
                    }

                    LOGGER.log(System.Logger.Level.INFO, "⭐  JKS Keystore and truststore generated successfully!");
                    LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD10  Key Store File: " + keyStoreFile.getAbsolutePath());

                    if (client != null) {
                        LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD13  Server Trust Store File: " + serverTrustStoreFile.getAbsolutePath());
                        LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD10  Client Key Store File: " + clientKeyStoreFile.getAbsolutePath());
                        LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD13  Client Trust Store File: " + trustStoreFile.getAbsolutePath());
                    } else {
                        LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD13  Trust Store File: " + trustStoreFile.getAbsolutePath());
                    }
                } else if (format == Format.PKCS12) {
                    File keyStoreFile = new File(root,  request.name() + "-keystore." + format.extension());
                    File trustStoreFile = new File(root, request.name() + (client!=null ? "-client" : "") + "-truststore." + format.extension());

                    File clientKeyStoreFile = new File(root,  request.name() + "-client-keystore." + format.extension());
                    File serverTrustStoreFile = new File(root,  request.name() + "-server-truststore." + format.extension());

                    writePrivateKeyAndCertificateToPKCS12(certificate, keyPair, keyStoreFile, request.password().toCharArray(), request.getAlias());
                    writeTrustStoreToPKCS12(Map.of(request.getAlias(), certificate), trustStoreFile, request.password().toCharArray());

                    if (client != null) {
                        writePrivateKeyAndCertificateToPKCS12(clientCertificate, clientKeyPair, clientKeyStoreFile, request.password().toCharArray(), request.getAlias());
                        writeTrustStoreToPKCS12(Map.of(request.getAlias(), clientCertificate), serverTrustStoreFile, request.password().toCharArray());
                    }


                    LOGGER.log(System.Logger.Level.INFO, "⭐  PCKS12 Keystore and truststore generated successfully!");
                    if (client != null) {
                        LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD13  Server Trust Store File: " + serverTrustStoreFile.getAbsolutePath());
                        LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD10  Client Key Store File: " + clientKeyStoreFile.getAbsolutePath());
                        LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD13  Client Trust Store File: " + trustStoreFile.getAbsolutePath());
                    } else {
                        LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD13  Trust Store File: " + trustStoreFile.getAbsolutePath());
                    }
                } else {
                    throw new IllegalArgumentException("Unsupported format " + format);
                }

            }
        } catch (Exception e) {
            LOGGER.log(System.Logger.Level.ERROR, "Error while generating the certificates", e);
            throw e;
        }
    }

}
