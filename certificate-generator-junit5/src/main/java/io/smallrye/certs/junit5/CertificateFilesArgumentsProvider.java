package io.smallrye.certs.junit5;

import java.util.Arrays;
import java.util.stream.Stream;

import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.provider.AnnotationBasedArgumentsProvider;
import org.junit.jupiter.params.provider.Arguments;

import io.smallrye.certs.CertificateFiles;

public class CertificateFilesArgumentsProvider extends AnnotationBasedArgumentsProvider<CertificatesSource> {
    @Override
    protected Stream<? extends Arguments> provideArguments(ExtensionContext extensionContext, CertificatesSource certificatesSource) {
        CertificateGenerationExtension extension = CertificateGenerationExtension.getInstance(extensionContext);
        Stream<CertificateFiles> stream = extension.certificateFiles.stream();
        if (certificatesSource.names().length > 0) {
            stream = stream.filter(certificateFiles -> Arrays.stream(certificatesSource.names())
                    .anyMatch(name -> name.equals(certificateFiles.name())));
        }
        if (certificatesSource.formats().length > 0) {
            stream = stream.filter(certificateFiles -> Arrays.stream(certificatesSource.formats())
                    .anyMatch(name -> name.equals(certificateFiles.format())));
        }
        return stream.map(Arguments::of);
    }
}
