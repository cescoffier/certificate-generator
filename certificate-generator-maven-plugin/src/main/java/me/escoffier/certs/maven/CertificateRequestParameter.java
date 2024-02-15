package me.escoffier.certs.maven;

import me.escoffier.certs.CertificateRequest;
import org.apache.maven.plugins.annotations.Parameter;

import java.util.List;

public class CertificateRequestParameter {

    @Parameter(required = true)
    private String name;
    @Parameter
    private String password;
    @Parameter(defaultValue = "localhost")
    private String cn;
    @Parameter
    private String alias;
    @Parameter(required = true)
    private List<String> formats;
    @Parameter(defaultValue = "2")
    private int duration;
    @Parameter(defaultValue = "false")
    private boolean client;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getCn() {
        return cn;
    }

    public void setCn(String cn) {
        this.cn = cn;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public List<String> getFormats() {
        return formats;
    }

    public void setFormats(List<String> formats) {
        this.formats = formats;
    }

    public int getDuration() {
        return duration;
    }

    public void setDuration(int duration) {
        this.duration = duration;
    }

    public boolean isClient() {
        return client;
    }

    public void setClient(boolean client) {
        this.client = client;
    }
}
