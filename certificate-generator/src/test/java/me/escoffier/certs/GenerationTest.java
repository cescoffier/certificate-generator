package me.escoffier.certs;

import io.vertx.core.Vertx;
import io.vertx.core.net.*;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.resource.Dir;

import java.io.File;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

public class GenerationTest {

    private static Vertx vertx;

    @BeforeAll
    static void initVertx() {
        vertx = Vertx.vertx();
    }

    @AfterAll
    static void closeVertx() {
        vertx.close().toCompletionStage().toCompletableFuture().join();
    }

    @Test
    void JKSGeneration(@Dir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withFormat(Format.JKS)
                .withPassword("password");
        new CertificateGenerator(tempDir, true).generate(request);

        KeyCertOptions serverOptions = new JksOptions().setPath(new File(tempDir.toFile(), "test-keystore.jks").getAbsolutePath()).setPassword("password");
        TrustOptions clientOptions = new JksOptions().setPath(new File(tempDir.toFile(), "test-truststore.jks").getAbsolutePath()).setPassword("password");
        var server = VertxHttpHelper.createHttpServer(vertx, serverOptions);
        var response = VertxHttpHelper.createHttpClientAndInvoke(vertx, server, clientOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void JKSGenerationWithDifferentAlias(@Dir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withAlias("alias")
                .withFormat(Format.JKS)
                .withPassword("password");
        new CertificateGenerator(tempDir, true).generate(request);

        KeyCertOptions serverOptions = new JksOptions().setPath(new File(tempDir.toFile(), "test-keystore.jks").getAbsolutePath()).setPassword("password").setAlias("alias");
        TrustOptions clientOptions = new JksOptions().setPath(new File(tempDir.toFile(), "test-truststore.jks").getAbsolutePath()).setPassword("password").setAlias("alias");
        var server = VertxHttpHelper.createHttpServer(vertx, serverOptions);
        var response = VertxHttpHelper.createHttpClientAndInvoke(vertx, server, clientOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void PEMGeneration(@Dir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withFormat(Format.PEM);
        new CertificateGenerator(tempDir, true).generate(request);

        KeyCertOptions serverOptions = new PemKeyCertOptions()
                .addKeyPath(new File(tempDir.toFile(), "test.key").getAbsolutePath())
                .addCertPath(new File(tempDir.toFile(), "test.crt").getAbsolutePath());
        TrustOptions clientOptions = new PemTrustOptions().addCertPath(new File(tempDir.toFile(), "test-ca.crt").getAbsolutePath());
        var server = VertxHttpHelper.createHttpServer(vertx, serverOptions);
        var response = VertxHttpHelper.createHttpClientAndInvoke(vertx, server, clientOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void PCKS12Generation(@Dir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withFormat(Format.PKCS12)
                .withPassword("secret");
        new CertificateGenerator(tempDir, true).generate(request);

        KeyCertOptions serverOptions = new PfxOptions().setPath(new File(tempDir.toFile(), "test-keystore.p12").getAbsolutePath()).setPassword("secret");
        TrustOptions clientOptions = new PfxOptions().setPath(new File(tempDir.toFile(), "test-truststore.p12").getAbsolutePath()).setPassword("secret");
        var server = VertxHttpHelper.createHttpServer(vertx, serverOptions);
        var response = VertxHttpHelper.createHttpClientAndInvoke(vertx, server, clientOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void multiFormatGeneration(@Dir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withFormat(Format.PKCS12)
                .withFormat(Format.PEM)
                .withPassword("password");
        new CertificateGenerator(tempDir, true).generate(request);

        KeyCertOptions serverOptions = new PfxOptions().setPath(new File(tempDir.toFile(), "test-keystore.p12").getAbsolutePath()).setPassword("password");
        TrustOptions clientOptions = new PemTrustOptions().addCertPath(new File(tempDir.toFile(), "test-ca.crt").getAbsolutePath());
        var server = VertxHttpHelper.createHttpServer(vertx, serverOptions);
        var response = VertxHttpHelper.createHttpClientAndInvoke(vertx, server, clientOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void mTLSWithPemGeneration(@Dir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withClientCertificate()
                .withFormat(Format.PEM);
        new CertificateGenerator(tempDir, true).generate(request);

        KeyCertOptions serverOptions = new PemKeyCertOptions()
                .addKeyPath(new File(tempDir.toFile(), "test.key").getAbsolutePath())
                .addCertPath(new File(tempDir.toFile(), "test.crt").getAbsolutePath());
        PemTrustOptions serverTrustOptions = new PemTrustOptions().addCertPath(new File(tempDir.toFile(), "test-server-ca.crt").getAbsolutePath());

        KeyCertOptions clientOptions = new PemKeyCertOptions()
                .addKeyPath(new File(tempDir.toFile(), "test-client.key").getAbsolutePath())
                .addCertPath(new File(tempDir.toFile(), "test-client.crt").getAbsolutePath());
        TrustOptions clientTrustOptions = new PemTrustOptions().addCertPath(new File(tempDir.toFile(), "test-client-ca.crt").getAbsolutePath());
        var server = VertxHttpHelper.createHttpServerWithMutualAuth(vertx, serverOptions, serverTrustOptions);
        var response = VertxHttpHelper.createHttpClientWithMutualAuthAndInvoke(vertx, server, clientOptions, clientTrustOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void mTLSWithJKSGeneration(@Dir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withPassword("secret")
                .withAlias("alias")
                .withClientCertificate()
                .withFormat(Format.JKS);
        new CertificateGenerator(tempDir, true).generate(request);


        KeyCertOptions serverOptions = new JksOptions().setPath(new File(tempDir.toFile(), "test-keystore.jks").getAbsolutePath()).setPassword("secret").setAlias("alias");
        TrustOptions serverTrustOptions = new JksOptions().setPath(new File(tempDir.toFile(), "test-server-truststore.jks").getAbsolutePath()).setPassword("secret").setAlias("alias");

        KeyCertOptions clientOptions = new JksOptions().setPath(new File(tempDir.toFile(), "test-client-keystore.jks").getAbsolutePath()).setPassword("secret").setAlias("alias");
        TrustOptions clientTrustOptions = new JksOptions().setPath(new File(tempDir.toFile(), "test-client-truststore.jks").getAbsolutePath()).setPassword("secret").setAlias("alias");

        var server = VertxHttpHelper.createHttpServerWithMutualAuth(vertx, serverOptions, serverTrustOptions);
        var response = VertxHttpHelper.createHttpClientWithMutualAuthAndInvoke(vertx, server, clientOptions, clientTrustOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void mTLSWithPKCS12Generation(@Dir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withPassword("secret")
                .withAlias("alias")
                .withClientCertificate()
                .withFormat(Format.PKCS12);
        new CertificateGenerator(tempDir, true).generate(request);


        KeyCertOptions serverOptions = new PfxOptions().setPath(new File(tempDir.toFile(), "test-keystore.p12").getAbsolutePath()).setPassword("secret").setAlias("alias");
        TrustOptions serverTrustOptions = new PfxOptions().setPath(new File(tempDir.toFile(), "test-server-truststore.p12").getAbsolutePath()).setPassword("secret").setAlias("alias");

        KeyCertOptions clientOptions = new PfxOptions().setPath(new File(tempDir.toFile(), "test-client-keystore.p12").getAbsolutePath()).setPassword("secret").setAlias("alias");
        TrustOptions clientTrustOptions = new PfxOptions().setPath(new File(tempDir.toFile(), "test-client-truststore.p12").getAbsolutePath()).setPassword("secret").setAlias("alias");

        var server = VertxHttpHelper.createHttpServerWithMutualAuth(vertx, serverOptions, serverTrustOptions);
        var response = VertxHttpHelper.createHttpClientWithMutualAuthAndInvoke(vertx, server, clientOptions, clientTrustOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void mTLSWithJKSAndPemGeneration(@Dir Path tempDir) throws Exception {
        CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withPassword("secret")
                .withAlias("alias")
                .withClientCertificate()
                .withFormat(Format.JKS)
                .withFormat(Format.PEM);
        new CertificateGenerator(tempDir, true).generate(request);


        KeyCertOptions serverOptions = new JksOptions().setPath(new File(tempDir.toFile(), "test-keystore.jks").getAbsolutePath()).setPassword("secret").setAlias("alias");
        TrustOptions serverTrustOptions = new JksOptions().setPath(new File(tempDir.toFile(), "test-server-truststore.jks").getAbsolutePath()).setPassword("secret").setAlias("alias");

        KeyCertOptions clientOptions = new PemKeyCertOptions()
                .addKeyPath(new File(tempDir.toFile(), "test-client.key").getAbsolutePath())
                .addCertPath(new File(tempDir.toFile(), "test-client.crt").getAbsolutePath());
        TrustOptions clientTrustOptions = new PemTrustOptions().addCertPath(new File(tempDir.toFile(), "test-client-ca.crt").getAbsolutePath());

        var server = VertxHttpHelper.createHttpServerWithMutualAuth(vertx, serverOptions, serverTrustOptions);
        var response = VertxHttpHelper.createHttpClientWithMutualAuthAndInvoke(vertx, server, clientOptions, clientTrustOptions);

        assertThat(response.statusCode()).isEqualTo(200);
    }

}
