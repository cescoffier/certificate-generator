package me.escoffier.certs.junit5;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.junit.jupiter.params.provider.ArgumentsSource;

import me.escoffier.certs.Format;

@Target({ElementType.ANNOTATION_TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@ArgumentsSource(CertificateFilesArgumentsProvider.class)
public @interface CertificatesSource {
    String[] names() default {};

    Format[] formats() default {};
}
