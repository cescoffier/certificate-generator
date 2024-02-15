# Certificate Generator

An API and a Maven plugin to generate certificates.
The main goal is to provide an easy way to generate self-signed certificates for testing purposes.
Thus, the test can used the generated certificates to test the application.

## Features

- JKS, PEM and PKCS12 format support
- mTLS (client and server) generation support
- Maven plugin to generate certificates
- Junit 5 extension to generate certificates in tests

## Generated files

Here is the list of generated files:

**Format: JKS and server only (no mTLS)**

- 🔐  Key Store File: $DIR/$NAME-keystore.jks
- 🔓  Trust Store File: %DIR/$NAME-truststore.jks (to be deployed on the client-side)

**Format: PEM and server only (no mTLS)**

- 🔑  Key File: $DIR/$NAME-key.pem
- 📜  Cert File: $DIR/$NAME-cert.pem
- 🔓  Trust Store File: $DIR/$NAME-truststore.pem (to be deployed on the client-side)

**Format: PKCS12 and server only (no mTLS)**

- 🔐  Key Store File: $DIR/$NAME-keystore.p12
- 🔓  Trust Store File: %DIR/$NAME-truststore.p12 (to be deployed on the client-side)

**Format: JKS and mTLS**

- 🔐  Key Store File: DIR/$NAME-keystore.jks (to be deployed on the server-side)
- 🔓  Server Trust Store File: $DIR/$NAME-server-truststore.jks (to be deployed on the server-side, contains the client certificate)
- 🔐  Client Key Store File: $DIR/$NAME-client-keystore.jks (to be deployed on the client-side)
- 🔓  Client Trust Store File: $DIR/$NAME-client-truststore.jks (to be deployed on the client-side, contains the server certificate)

** Format: PEM and mTLS**

- 🔑  Key File: $DIR/$NAME-key.pem (to be deployed on the server-side)
- 📜  Cert File: $DIR/$NAME-cert.pem (to be deployed on the server-side)
- 🔓  Server Trust Store File: $DIR/$NAME-server-truststore.pem (to be deployed on the server-side, contains the client certificate)
- 🔑  Client Key File: $DIR/$NAME-client-key.pem (to be deployed on the client-side)
- 📜  Client Cert File: $DIR/$NAME-client-cert.pem (to be deployed on the client-side)
- 🔓  Client Trust Store File: $DIR/$NAME-client-truststore.pem (to be deployed on the client-side, contains the server certificate)


**Format: PKCS12 and mTLS**

- 🔐  Key Store File: DIR/$NAME-keystore.p12 (to be deployed on the server-side)
- 🔓  Server Trust Store File: $DIR/$NAME-server-truststore.p12 (to be deployed on the server-side, contains the client certificate)
- 🔐  Client Key Store File: $DIR/$NAME-client-keystore.p12 (to be deployed on the client-side)
- 🔓  Client Trust Store File: $DIR/$NAME-client-truststore.p12 (to be deployed on the client-side, contains the server certificate)

## Junit 5 extension

The project provides a JUnit 5 extension to generate certificates for each test.
The certificates are generated before any test of the test case run (like a `@BeforeAll`).

To use the Junit 5 extension, add the following dependency to your project:

```xml
<dependency>
    <groupId>me.escoffier.certs</groupId>
    <artifactId>certificate-generator-junit5</artifactId>
    <version>${VERSION}</version>
    <scope>test</scope>
</dependency>
```

Then, you can use the `@Certificates` annotation to generate certificates for your test:

```java
@Certificates(
    baseDir = "target/certificates",
    certificates = {
        @Certificate(name = "reload-C", password = "secret", formats = Format.PEM),
        @Certificate(name = "reload-D", password = "secret", formats = Format.PEM),
    }
)
```

## Maven Plugin Usage

Here is an example of the Maven plugin usage:

```xml
<plugin>
    <groupId>me.escoffier.certs</groupId>
    <artifactId>certificate-generator-maven-plugin</artifactId>
    <version>${VERSION}</version>
    <executions>
        <execution>
            <phase>generate-test-resources</phase>
            <goals>
                <goal>generate</goal>
            </goals>
        </execution>
    </executions>
    <configuration>
        <certificates>
            <certificate>
                <name>reload-A</name> <!-- the name of the certificate -->
                <formats>  <!-- List of formats to generate, are supported PEM, JKS and PKCS12 -->
                    <format>PEM</format>
                    <format>PKCS12</format>
                </formats>
                <password>secret</password> <!-- Password for the key store if supported -->
                <alias>alias</alias> <!-- Alias for the key if supported, reuse `name` if not set -->
                <cn>localhost</cn> <!-- Common Name -->
                <duration>2</duration> <!-- in days -->
                <client>true</client> <!-- Generate a client certificate -->
            </certificate>
            <certificate>
                <name>reload-B</name>
                <formats>
                    <format>PEM</format>
                    <format>PKCS12</format>
                </formats>
                <duration>365</duration>
                <password>secret</password>
                <alias>alias</alias>
            </certificate>
        </certificates>
    </configuration>
</plugin>
```

## API Usage

First, you need to add the following dependency to your project:

```xml
<dependency>    
  <groupId>me.escoffier.certs</groupId>
  <artifactId>certificate-generator</artifactId>
   <version>${VERSION}</version>
    <scope>test</scope>  
</dependency>
```

Then, uou can use the `me.escoffier.certs.CertificateGenerator` API to generate certificates programmatically:

```java
CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withPassword("secret")
                .withAlias("alias")
                .withClientCertificate()
                .withFormat(Format.JKS)
                .withFormat(Format.PEM);
        new CertificateGenerator(tempDir).generate(request);
```


