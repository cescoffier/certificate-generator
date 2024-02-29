package me.escoffier.certs.junit5;

import me.escoffier.certs.CertificateFiles;
import me.escoffier.certs.CertificateGenerator;
import me.escoffier.certs.CertificateRequest;

import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolutionException;
import org.junit.jupiter.api.extension.ParameterResolver;
import org.junit.platform.commons.util.AnnotationUtils;

import java.io.File;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class CertificateGenerationExtension implements BeforeAllCallback, ParameterResolver {

    public static CertificateGenerationExtension getInstance(ExtensionContext extensionContext) {
        return extensionContext.getStore(ExtensionContext.Namespace.GLOBAL)
                .get(CertificateGenerationExtension.class, CertificateGenerationExtension.class);
    }

    List<CertificateFiles> certificateFiles = new ArrayList<>();

    @Override
    public void beforeAll(ExtensionContext extensionContext) throws Exception {
        extensionContext.getStore(ExtensionContext.Namespace.GLOBAL)
                .getOrComputeIfAbsent(CertificateGenerationExtension.class, c -> this);
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
                    .withClientCertificate(certificate.client())
                    .withFormats(Arrays.asList(certificate.formats()))
                    .withAlias(certificate.alias().isEmpty() ? null : certificate.alias())
                    .withCN(certificate.cn())
                    .withPassword(certificate.password().isEmpty() ? null : certificate.password())
                    .withDuration(Duration.ofDays(certificate.duration()));

            certificateFiles.addAll(generator.generate(request));
        }
    }

    @Override
    public boolean supportsParameter(ParameterContext parameterContext, ExtensionContext extensionContext) throws ParameterResolutionException {
        if (extensionContext.getRequiredTestMethod().isAnnotationPresent(CertificatesSource.class)) {
            return false;
        }
        if (parameterContext.getParameter().getParameterizedType() instanceof ParameterizedType type) {
            if (((Class<?>) type.getRawType()).isAssignableFrom(List.class)) {
                Type argument = type.getActualTypeArguments()[0];
                return CertificateFiles.class.isAssignableFrom((Class<?>) argument);
            } else {
                return false;
            }
        } else {
            return CertificateFiles.class.isAssignableFrom(parameterContext.getParameter().getType());
        }
    }

    @Override
    public Object resolveParameter(ParameterContext parameterContext, ExtensionContext extensionContext) throws ParameterResolutionException {
        if (parameterContext.getParameter().getParameterizedType() instanceof ParameterizedType type) {
            if (((Class<?>) type.getRawType()).isAssignableFrom(List.class)) {
                Type argument = type.getActualTypeArguments()[0];
                return certificateFiles.stream()
                        .filter(f -> ((Class<?>) argument).isAssignableFrom(f.getClass()))
                        .collect(Collectors.toList());
            } else {
                return null;
            }
        } else {
            return certificateFiles.stream()
                    .filter(f -> parameterContext.getParameter().getType().isAssignableFrom(f.getClass()))
                    .findFirst()
                    .orElse(null);
        }
    }

}
