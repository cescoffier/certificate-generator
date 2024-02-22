package me.escoffier.certs.junit5;

import me.escoffier.certs.CertificateGenerator;
import me.escoffier.certs.CertificateRequest;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.platform.commons.util.AnnotationUtils;

import java.io.File;
import java.time.Duration;
import java.util.Arrays;

public class CertificateGenerationExtension implements BeforeAllCallback {
    @Override
    public void beforeAll(ExtensionContext extensionContext) throws Exception {
        var maybe = AnnotationUtils.findAnnotation(extensionContext.getRequiredTestClass(), Certificates.class);
        if (maybe.isEmpty()) {
            return;
        }
        var annotation = maybe.get();
        for (Certificate certificate : annotation.certificates()) {
            String baseDir = annotation.baseDir();
            File file = new File(baseDir);
            file.mkdirs();
            CertificateGenerator generator = new CertificateGenerator(file.toPath(), annotation.replaceIfExists());

            CertificateRequest request = new CertificateRequest()
                    .withName(certificate.name())
                    .withFormats(Arrays.asList(certificate.formats()))
                    .withAlias(certificate.alias().isEmpty() ? null : certificate.alias())
                    .withCN(certificate.cn())
                    .withPassword(certificate.password().isEmpty() ? null : certificate.password())
                    .withDuration(Duration.ofDays(certificate.duration()));

            generator.generate(request);
        }
    }


}
