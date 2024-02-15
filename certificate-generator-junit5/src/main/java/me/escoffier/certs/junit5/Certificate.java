package me.escoffier.certs.junit5;

import me.escoffier.certs.Format;

public @interface Certificate {

    /**
     * Sets the name of the certificate.
     */
    String name();

    /**
     * Sets the formats of the certificate, are supported: JKS, PEM and PKCS12.
     */
    Format[] formats();

    /**
     * Sets the password of the certificate if needed.
     */
    String password() default "";

    /**
     * Sets the duration of the certificate in days.
     */
    int duration() default 2;

    /**
     * Sets the CN (common name) of the certificate.
     */
    String cn() default "localhost";

    /**
     * Sets the alias of the certificate.
     */
    String alias() default "";

    /**
     * Sets whether the certificate is a client certificate. This is useful for mutual TLS.
     */
    boolean client() default false;

}
