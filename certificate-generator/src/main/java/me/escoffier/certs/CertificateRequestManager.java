package me.escoffier.certs;

import java.io.File;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static me.escoffier.certs.CertificateUtils.*;

public class CertificateRequestManager {

    /**
     * The request used to generate the certificates.
     */
    private final CertificateRequest request;
    /**
     * The main certificate name.
     */
    private final String name;
    /**
     * Stored the different requested certificates.
     */
    Map<String, CertificateHolder> holders = new HashMap<>();

    public CertificateRequestManager(CertificateRequest request) throws Exception {
        this.request = request;
        this.name = request.name();

        // This is a very annoying behavior that need to be investigated.
        // When combining PEM with JKS or P12, certificate validation fails.
        boolean useSameCert = request.formats().contains(Format.PEM)  && request.formats().size() > 1;

        holders.put(request.name(), new CertificateHolder(request.getCN(), request.getSubjectAlternativeNames(), request.getDuration(), request.hasClient(), request.getPassword(), useSameCert));

        for (String alias : request.aliases().keySet()) {
            AliasRequest nested = request.aliases().get(alias);
            // We use the duration of the main certificate.
            holders.put(alias, new CertificateHolder(nested.getCN(), nested.getSubjectAlternativeNames(), request.getDuration(), nested.hasClient(), nested.getPassword(), useSameCert));
        }
    }

    public CertificateHolder getCertificateHolder(String alias) {
        return holders.get(alias);
    }

    public CertificateHolder getMainCertificateHolder() {
        return holders.get(name);
    }

    public List<CertificateFiles> generate(Path root, boolean replaceIfExists) throws Exception {
        List<CertificateFiles> output = new ArrayList<>();
        for (Format format : request.formats()) {
            switch (format) {
                case PEM -> output.addAll(generatePemCertificates(root, replaceIfExists));
                case JKS -> output.add(generateJksCertificates(root, replaceIfExists));
                case PKCS12 -> output.add(generatePkcs12Certificates(root, replaceIfExists));
            }
        }
        return output;
    }

    private CertificateFiles generateJksCertificates(Path root, boolean replaceIfExists) throws Exception {
        JksCertificateFiles files = new JksCertificateFiles(root, name, request.hasClient(), request.getPassword());

        if (replaceIfExists || !files.keyStoreFile().toFile().isFile()) {
            CertificateUtils.writePrivateKeyAndCertificateToJKS(holders, request.getPassword(), files.keyStoreFile().toFile());
        }
        if (replaceIfExists || !files.trustStoreFile().toFile().isFile()) {
            // Client truststore.
            CertificateUtils.writeTrustStoreToJKS(holders, files.trustStoreFile().toFile(), request.getPassword().toCharArray());
        }

        Map<String, CertificateHolder> clients = new HashMap<>();
        for (Map.Entry<String, CertificateHolder> entry : holders.entrySet()) {
            if (entry.getValue().hasClient()) {
                clients.put(entry.getKey(), entry.getValue());
            }
        }

        if (! clients.isEmpty()) {
            if (replaceIfExists || !files.clientKeyStoreFile().toFile().isFile()) {
                CertificateUtils.writePrivateKeyAndCertificateToJKS(clients, request.getPassword(), files.clientKeyStoreFile().toFile());
            }
            if (replaceIfExists || !files.serverTrustStoreFile().toFile().isFile()) {
                CertificateUtils.writeTrustStoreToJKS(clients, files.serverTrustStoreFile().toFile(), request.getPassword().toCharArray());
            }
        }

        return files;
    }

    private CertificateFiles generatePkcs12Certificates(Path root, boolean replaceIfExists) throws Exception {
        Pkcs12CertificateFiles files = new Pkcs12CertificateFiles(root, name, request.hasClient(), request.getPassword());

        if (replaceIfExists || !files.keyStoreFile().toFile().isFile()) {
            CertificateUtils.writePrivateKeyAndCertificateToPKCS12(holders, files.keyStoreFile().toFile(), request.getPassword().toCharArray());
        }
        if (replaceIfExists || !files.trustStoreFile().toFile().isFile()) {
            CertificateUtils.writeTrustStoreToPKCS12(holders, files.trustStoreFile().toFile(), request.getPassword().toCharArray());
        }

        Map<String, CertificateHolder> clients = new HashMap<>();
        for (Map.Entry<String, CertificateHolder> entry : holders.entrySet()) {
            if (entry.getValue().hasClient()) {
                clients.put(entry.getKey(), entry.getValue());
            }
        }

        if (! clients.isEmpty()) {
            if (replaceIfExists || !files.clientKeyStoreFile().toFile().isFile()) {
                CertificateUtils.writePrivateKeyAndCertificateToPKCS12(clients, files.clientKeyStoreFile().toFile(), request.getPassword().toCharArray());
            }
            if (replaceIfExists || !files.serverTrustStoreFile().toFile().isFile()) {
                CertificateUtils.writeTrustStoreToPKCS12(clients, files.serverTrustStoreFile().toFile(), request.getPassword().toCharArray());
            }
        }

        return files;
    }

    private List<CertificateFiles> generatePemCertificates(Path root, boolean replaceIfExists) throws Exception {
        List<CertificateFiles> files = new ArrayList<>();

        for (Map.Entry<String, CertificateHolder> entry : holders.entrySet()) {
            String alias = entry.getKey();
            CertificateHolder holder = entry.getValue();
            files.add(writePem(alias, holder, root, replaceIfExists));
        }

        return files;
    }

    private CertificateFiles writePem(String name, CertificateHolder holder, Path root, boolean replaceIfExists) throws Exception {
        PemCertificateFiles files = new PemCertificateFiles(root, name, holder.hasClient());

        X509Certificate serverCert = holder.certificate();
        X509Certificate clientCert = holder.clientCertificate();
        KeyPair serverKey = holder.keys();
        KeyPair clientKey = holder.clientKeys();

        File certFile = files.certFile().toFile();
        File keyFile = files.keyFile().toFile();
        File clientTrustFile = files.trustFile().toFile();
        File clientCertFile = files.clientCertFile().toFile();
        File clientKeyFile = files.clientKeyFile().toFile();
        File serverTrustfile = files.serverTrustFile().toFile();

        if (replaceIfExists || !certFile.isFile()) {
            CertificateUtils.writeCertificateToPEM(serverCert, certFile);
        }
        if (replaceIfExists || !keyFile.isFile()) {
            CertificateUtils.writePrivateKeyToPem(serverKey.getPrivate(), keyFile);
        }
        if (replaceIfExists || !clientTrustFile.isFile()) {
            writeTruststoreToPem(List.of(serverCert), clientTrustFile);
        }

        if (holder.hasClient()) {
            if (replaceIfExists || !clientCertFile.isFile()) {
                CertificateUtils.writeCertificateToPEM(clientCert, clientCertFile);
            }
            if (replaceIfExists || !clientKeyFile.isFile()) {
                CertificateUtils.writePrivateKeyToPem(clientKey.getPrivate(), clientKeyFile);
            }
            if (replaceIfExists || !serverTrustfile.isFile()) {
                writeTruststoreToPem(List.of(clientCert), serverTrustfile);
            }
        }

        return files;
    }
}
