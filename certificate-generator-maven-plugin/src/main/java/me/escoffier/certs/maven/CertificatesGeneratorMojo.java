package me.escoffier.certs.maven;

import me.escoffier.certs.CertificateGenerator;
import me.escoffier.certs.CertificateRequest;
import me.escoffier.certs.Format;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.io.File;
import java.time.Duration;
import java.util.List;

@Mojo(name = "generate", defaultPhase = LifecyclePhase.GENERATE_TEST_RESOURCES, threadSafe = true, requiresProject = true)
public class CertificatesGeneratorMojo extends AbstractMojo {


    @Parameter(required = true)
    private List<CertificateRequestParameter> certificates;

    @Parameter(property = "certificate-generator.outputDirectory", defaultValue = "${project.build.directory}/certificates")
    private String outputDirectory;

    @Override
    public void execute() throws MojoExecutionException {
        getLog().info("Generating certificates");

        var out = new File(outputDirectory);
        if (! out.isDirectory()) {
            out.mkdirs();
        }

        try {
            CertificateGenerator generator = new CertificateGenerator(new File(outputDirectory).toPath());
            for (CertificateRequestParameter request : certificates) {
                CertificateRequest cr = new CertificateRequest()
                        .withName(request.getName())
                        .withFormats(request.getFormats().stream().map(String::toUpperCase).map(Format::valueOf).toList())
                        .withAlias(request.getAlias())
                        .withClientCertificate(request.isClient())
                        .withCN(request.getCn())
                        .withPassword(request.getPassword())
                        .withDuration(Duration.ofDays(request.getDuration()));

                generator.generate(cr);
            }



        } catch (Exception e) {
            throw new MojoExecutionException("Unable to generate certificates", e);
        }
    }

    public void setCertificates(List<CertificateRequestParameter> requests) {
        this.certificates = requests;
    }
}
