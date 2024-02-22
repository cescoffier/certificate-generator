package me.escoffier.certs.junit5;

import org.junit.jupiter.api.extension.ExtendWith;

import java.lang.annotation.*;

/**
 * Generate certificates before running tests.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@ExtendWith(CertificateGenerationExtension.class)
@Inherited
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

    /**
     * Whether to replace the certificates if they already exist.
     */
    boolean replaceIfExists() default false;
}
