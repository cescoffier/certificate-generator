package me.escoffier.certs;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

public final class CertificateRequest {
    private String name;
    private String alias;
    private String password;
    private List<Format> formats = new ArrayList<>();
    private Duration duration = Duration.ofDays(2);
    private String cn = "localhost";

    private boolean client = false;


    public CertificateRequest withName(String name) {
        this.name = name;
        return this;
    }

    public CertificateRequest withAlias(String alias) {
        this.alias = alias;
        return this;
    }

    public CertificateRequest withPassword(String password) {
        this.password = password;
        return this;
    }

    public CertificateRequest withFormats(List<Format> formats) {
        this.formats = formats;
        return this;
    }

    public CertificateRequest withFormat(Format format) {
        this.formats.add(format);
        return this;
    }

    public CertificateRequest withDuration(Duration duration) {
        this.duration = duration;
        return this;
    }

    public CertificateRequest withCN(String cn) {
        this.cn = cn;
        return this;
    }

    public CertificateRequest withClientCertificate() {
        this.client = true;
        return this;
    }

    public CertificateRequest withClientCertificate(boolean client) {
        this.client = client;
        return this;
    }

    void validate() {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("The name of the certificate must be set");
        }
        if (formats.isEmpty()) {
            formats.add(Format.PEM);
        }
        if (cn == null || cn.isEmpty()) {
            cn = "localhost";
        }
    }


    public String getCN() {
        return cn;
    }

    public Duration getDuration() {
        return duration;
    }

    public String getAlias() {
        if (alias == null || alias.isEmpty()) {
            return name;
        }
        return alias;
    }

    public String name() {
        return name;
    }


    public String password() {
        return password;
    }

    public List<Format> formats() {
        return formats;
    }

    public boolean client() {
        return client;
    }


}
