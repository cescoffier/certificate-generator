package io.smallrye.certs;

import java.nio.file.Path;

public final class JksCertificateFiles implements CertificateFiles {

    private final Path root;
    private final String name;
    private final boolean client;
    private final String password;

    private final Path keyStoreFile;
    private final Path trustStoreFile;
    private final Path clientKeyStoreFile;
    private final Path serverTrustStoreFile;

    public JksCertificateFiles(Path root, String name, boolean client, String password) {
        this.root = root;
        this.name = name;
        this.client = client;
        this.password = password;
        this.keyStoreFile = root.resolve(name + "-keystore." + format().extension());
        this.trustStoreFile = root.resolve(name + (client ? "-client" : "") + "-truststore." + format().extension());
        this.clientKeyStoreFile = root.resolve(name + "-client-keystore." + format().extension());
        this.serverTrustStoreFile = root.resolve(name + "-server-truststore." + format().extension());
    }

    @Override
    public Format format() {
        return Format.JKS;
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public Path root() {
        return root;
    }

    @Override
    public boolean client() {
        return client;
    }

    @Override
    public String password() {
        return password;
    }

    @Override
    public Path trustStore() {
        return client ? serverTrustStoreFile: trustStoreFile;
    }

    @Override
    public String toString() {
        return "JksCertificateFiles{" +
                "root=" + root +
                ", name='" + name + '\'' +
                ", client=" + client +
                ", password='" + password + '\'' +
                '}';
    }

    public Path keyStoreFile() {
        return keyStoreFile;
    }

    public Path trustStoreFile() {
        return trustStoreFile;
    }

    public Path clientKeyStoreFile() {
        return clientKeyStoreFile;
    }

    public Path serverTrustStoreFile() {
        return serverTrustStoreFile;
    }

}
