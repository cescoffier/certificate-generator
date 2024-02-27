package me.escoffier.certs;

import java.nio.file.Path;

public final class PemCertificateFiles implements CertificateFiles {

    private final Path root;
    private final String name;
    private final boolean client;

    private final Path certFile;
    private final Path keyFile;
    private final Path trustFile;
    private final Path clientCertFile;
    private final Path clientKeyFile;
    private final Path serverTrustFile;

    public PemCertificateFiles(Path root, String name, boolean client) {
        this.root = root;
        this.name = name;
        this.client = client;
        this.certFile = root.resolve(name + ".crt");
        this.keyFile = root.resolve(name + ".key");
        this.trustFile = root.resolve(name + (client ? "-client" : "") + "-ca.crt");
        this.clientCertFile = root.resolve(name + "-client.crt");
        this.clientKeyFile = root.resolve(name + "-client.key");
        this.serverTrustFile = root.resolve(name + "-server-ca.crt");
    }

    @Override
    public Format format() {
        return Format.PEM;
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
        return null;
    }

    @Override
    public Path trustStore() {
        return client ? serverTrustFile : trustFile;
    }

    @Override
    public String toString() {
        return "PemCertificateFiles{" +
                "root=" + root +
                ", name='" + name + '\'' +
                ", client=" + client +
                '}';
    }

    public Path certFile() {
        return certFile;
    }

    public Path keyFile() {
        return keyFile;
    }

    public Path trustFile() {
        return trustFile;
    }

    public Path clientCertFile() {
        return clientCertFile;
    }

    public Path clientKeyFile() {
        return clientKeyFile;
    }

    public Path serverTrustFile() {
        return serverTrustFile;
    }

}
