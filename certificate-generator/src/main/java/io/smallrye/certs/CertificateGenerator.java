package io.smallrye.certs;

import java.io.File;
import java.nio.file.Path;
import java.util.List;

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

        CertificateRequestManager manager = new CertificateRequestManager(request);
        List<CertificateFiles> certificateFiles = manager.generate(root.toPath(), replaceIfExists);
        try {
            for (CertificateFiles file : certificateFiles) {
                if (file instanceof PemCertificateFiles) {
                    LOGGER.log(System.Logger.Level.INFO, "⭐  PEM certificates, keystore, and truststore named " + file.name() + " generated!");
                    LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD11  Key File: " + ((PemCertificateFiles) file).keyFile().toFile().getAbsolutePath());
                    LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDCDC  Cert File: " + ((PemCertificateFiles) file).certFile().toFile().getAbsolutePath());
                    if (file.client()) {
                        LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD13  Server Trust Store File: " + ((PemCertificateFiles) file).serverTrustFile().toFile().getAbsolutePath());
                        LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD11  Client Key File: " + ((PemCertificateFiles) file).clientKeyFile().toFile().getAbsolutePath());
                        LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDCDC  Client Cert File: " + ((PemCertificateFiles) file).clientCertFile().toFile().getAbsolutePath());
                        LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD13  Client Trust Store File: " + ((PemCertificateFiles) file).trustFile().toFile().getAbsolutePath());
                    } else {
                        LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD13  Trust Store File: " + file.trustStore().toFile().getAbsolutePath());
                    }
                } else if (file instanceof JksCertificateFiles) {
                    LOGGER.log(System.Logger.Level.INFO, "⭐  JKS keystore and truststore generated successfully!");
                    LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD10  Key Store File: " + ((JksCertificateFiles) file).keyStoreFile().toFile().getAbsolutePath());
                    if (file.client()) {
                        LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD13  Server Trust Store File: " + ((JksCertificateFiles) file).serverTrustStoreFile().toFile().getAbsolutePath());
                        LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD10  Client Key Store File: " + ((JksCertificateFiles) file).clientKeyStoreFile().toFile().getAbsolutePath());
                        LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD13  Client Trust Store File: " + ((JksCertificateFiles) file).trustStoreFile().toFile().getAbsolutePath());
                    } else {
                        LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD13  Trust Store File: " + file.trustStore().toFile().getAbsolutePath());
                    }
                } else if (file instanceof Pkcs12CertificateFiles) {
                    LOGGER.log(System.Logger.Level.INFO, "⭐  PKCS12 keystore and truststore generated successfully!");
                    LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD10  Key Store File: " + ((Pkcs12CertificateFiles) file).keyStoreFile().toFile().getAbsolutePath());
                    if (file.client()) {
                        LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD13  Server Trust Store File: " + ((Pkcs12CertificateFiles) file).serverTrustStoreFile().toFile().getAbsolutePath());
                        LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD10  Client Key Store File: " + ((Pkcs12CertificateFiles) file).clientKeyStoreFile().toFile().getAbsolutePath());
                        LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD13  Client Trust Store File: " + ((Pkcs12CertificateFiles) file).trustStoreFile().toFile().getAbsolutePath());
                    } else {
                        LOGGER.log(System.Logger.Level.INFO, "\uD83D\uDD13  Trust Store File: " + file.trustStore().toFile().getAbsolutePath());
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.log(System.Logger.Level.ERROR, "Error while generating the certificates", e);
            throw e;
        }
        return certificateFiles;
    }
}
