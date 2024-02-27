package me.escoffier.certs;

import java.io.File;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static me.escoffier.certs.CertificateUtils.*;

public class CertificateGenerator {

    final File root;

    static System.Logger LOGGER = System.getLogger(CertificateGenerator.class.getName());
    private final boolean replaceIfExists;

    public CertificateGenerator(Path tempDir, boolean replaceIfExists) {
        this.replaceIfExists = replaceIfExists;
        this.root = tempDir.toFile();
    }

    public CertificateGenerator() {
        root = new File(".");
        replaceIfExists = false;
    }

    public List<CertificateFiles> generate(CertificateRequest request) throws Exception {
        request.validate();
        List<CertificateFiles> certificateFiles = new ArrayList<>();
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
                    PemCertificateFiles files = new PemCertificateFiles(root.toPath(), request.name(), request.client());
                    certificateFiles.add(files);

                    File certFile = files.certFile().toFile();
                    File keyFile = files.keyFile().toFile();
                    File trustfile = files.trustFile().toFile();
                    File clientCertFile = files.clientCertFile().toFile();
                    File clientKeyFile = files.clientKeyFile().toFile();
                    File serverTrustfile = files.serverTrustFile().toFile();

                    if (replaceIfExists || !certFile.isFile()) {
                        writeCertificateToPEM(certificate, certFile);
                    }
                    if (replaceIfExists || !keyFile.isFile()) {
                        writePrivateKeyToPem(keyPair.getPrivate(), keyFile);
                    }
                    if (replaceIfExists || !trustfile.isFile()) {
                        writeTruststoreToPem(List.of(certificate), trustfile);
                    }

                    if (client != null) {
                        if (replaceIfExists || !clientCertFile.isFile()) {
                            writeCertificateToPEM(clientCertificate, clientCertFile);
                        }
                        if (replaceIfExists || !clientKeyFile.isFile()) {
                            writePrivateKeyToPem(clientKeyPair.getPrivate(), clientKeyFile);
                        }
                        if (replaceIfExists || !serverTrustfile.isFile()) {
                            writeTruststoreToPem(List.of(clientCertificate), serverTrustfile);
                        }
                    }

                    LOGGER.log(System.Logger.Level.INFO, "⭐  PEM Certificates, keystore, and truststore generated successfully!");
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
                    JksCertificateFiles files = new JksCertificateFiles(root.toPath(), request.name(), request.client(), request.password());
                    certificateFiles.add(files);

                    File keyStoreFile = files.keyStoreFile().toFile();
                    File trustStoreFile = files.trustStoreFile().toFile();

                    File clientKeyStoreFile = files.clientKeyStoreFile().toFile();
                    File serverTrustStoreFile = files.serverTrustStoreFile().toFile();

                    if (replaceIfExists || !keyStoreFile.isFile()) {
                        writePrivateKeyAndCertificateToJKS(certificate, keyPair, keyStoreFile, request.password().toCharArray(), request.getAlias());
                    }
                    if (replaceIfExists || !trustStoreFile.isFile()) {
                        writeTrustStoreToJKS(Map.of(request.getAlias(), certificate), trustStoreFile, request.password().toCharArray());
                    }

                    if (client != null) {
                        if (replaceIfExists || !clientKeyStoreFile.isFile()) {
                            writePrivateKeyAndCertificateToJKS(clientCertificate, clientKeyPair, clientKeyStoreFile, request.password().toCharArray(), request.getAlias());
                        }
                        if (replaceIfExists || !serverTrustStoreFile.isFile()) {
                            writeTrustStoreToJKS(Map.of(request.getAlias(), clientCertificate), serverTrustStoreFile, request.password().toCharArray());
                        }
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
                    Pkcs12CertificateFiles files = new Pkcs12CertificateFiles(root.toPath(), request.name(), request.client(), request.password());
                    certificateFiles.add(files);

                    File keyStoreFile = files.keyStoreFile().toFile();
                    File trustStoreFile = files.trustStoreFile().toFile();

                    File clientKeyStoreFile = files.clientKeyStoreFile().toFile();
                    File serverTrustStoreFile = files.serverTrustStoreFile().toFile();

                    if (replaceIfExists || !keyStoreFile.isFile()) {
                        writePrivateKeyAndCertificateToPKCS12(certificate, keyPair, keyStoreFile, request.password().toCharArray(), request.getAlias());
                    }
                    if (replaceIfExists || !trustStoreFile.isFile()) {
                        writeTrustStoreToPKCS12(Map.of(request.getAlias(), certificate), trustStoreFile, request.password().toCharArray());
                    }

                    if (client != null) {
                        if (replaceIfExists || !clientKeyStoreFile.isFile()) {
                            writePrivateKeyAndCertificateToPKCS12(clientCertificate, clientKeyPair, clientKeyStoreFile, request.password().toCharArray(), request.getAlias());
                        }
                        if (replaceIfExists || !serverTrustStoreFile.isFile()) {
                            writeTrustStoreToPKCS12(Map.of(request.getAlias(), clientCertificate), serverTrustStoreFile, request.password().toCharArray());
                        }
                    }

                    LOGGER.log(System.Logger.Level.INFO, "⭐  PCKS12 Keystore and truststore generated successfully!");
                    LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD10  Key Store File: " + keyStoreFile.getAbsolutePath());
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
        return certificateFiles;
    }

}
