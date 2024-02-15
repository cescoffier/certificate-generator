package me.escoffier.certs.junit5;

import org.junit.jupiter.api.extension.ExtendWith;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Generate certificates before running tests.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@ExtendWith(CertificateGenerationExtension.class)
public @interface Certificates {

    /**
     * The base directory in which certificates will be generated.
     */
    String baseDir();

    /**
     * The certificates to generate.
     * Must not be empty.
     */
    Certificate[] certificates();

}
