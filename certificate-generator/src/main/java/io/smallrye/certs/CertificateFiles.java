package io.smallrye.certs;

import java.nio.file.Path;

public sealed interface CertificateFiles permits JksCertificateFiles, PemCertificateFiles, Pkcs12CertificateFiles {

    String name();

    Format format();

    Path root();

    boolean client();

    String password();

    Path trustStore();

}
