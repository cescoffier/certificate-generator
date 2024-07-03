package io.smallrye.certs.ca;

import java.io.File;
import java.io.IOException;
import java.util.List;

import static java.lang.System.Logger.Level.*;

/**
 * A utility to install the CA certificate on Linux.
 * <p>
 * Each linux distribution has its own way to install the CA certificate.
 * <p>
 * Fedora commands works for Centos, Fedora, RHEL, etc.
 * Ubuntu commands works for Ubuntu, Debian, etc.
 */
public class LinuxCAInstaller {
    static System.Logger LOGGER = System.getLogger(CaGenerator.class.getName());


    private static final String FEDORA_LOCATION = "/etc/pki/ca-trust/source/anchors/";
    private static final String FEDORA_FILENAME = "/etc/pki/ca-trust/source/anchors/%s.pem";
    private static final List<String> FEDORA_COMMAND = List.of("sudo", "update-ca-trust", "extract");
    private static final String UBUNTU_LOCATION = "/usr/local/share/ca-certificates";
    private static final String UBUNTU_FILENAME = "/usr/local/share/ca-certificates/%s.crt";
    private static final List<String> UBUNTU_COMMAND = List.of("sudo", "update-ca-certificates");

    private static final String SUSE_LOCATION = "/usr/share/pki/trust/anchors";
    private static final String SUSE_FILENAME = "/usr/share/pki/trust/anchors/%s.pem";
    private static final List<String> SUSE_COMMAND = List.of("sudo", "update-ca-certificates");


    public static void installCAOnLinux(String cn, File ca) throws Exception {
        LOGGER.log(INFO, "🔥 Installing the CA certificate (issuer: {0}) into your operating system keychain. Your admin password may be asked.", cn);

        String certName = ca.getName().substring(0, ca.getName().lastIndexOf('.'));
        if (new File(FEDORA_LOCATION).isDirectory()) {
            String filename = String.format(FEDORA_FILENAME, certName);
            copy(ca, new File(filename));
            run(FEDORA_COMMAND);
        } else if (new File(UBUNTU_LOCATION).isDirectory()) {
            String filename = String.format(UBUNTU_FILENAME, certName);
            copy(ca, new File(filename));
            run(UBUNTU_COMMAND);
        } else if (new File(SUSE_LOCATION).isDirectory()) {
            String filename = String.format(SUSE_FILENAME, certName);
            copy(ca, new File(filename));
            run(SUSE_COMMAND);
        } else {
            LOGGER.log(ERROR, "❌ Unsupported Linux distribution, please install the CA certificate ({0}) manually", ca.getAbsolutePath());
        }

        LOGGER.log(WARNING, "❗️ Please restart your browser to take the changes into account. Some browser requires the certificate to be manually imported. " +
                "Please refer to the browser documentation, and import the certificate located at {0}", ca.getAbsolutePath());

    }


    private static void run(List<String> command) throws IOException, InterruptedException {
        LOGGER.log(DEBUG, "\t Executing command {0}", String.join(" ", command));
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.inheritIO();
        pb.start().waitFor();
    }

    private static void copy(File ca, File out) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("sudo", "cp", ca.getAbsolutePath(), out.getAbsolutePath());
        pb.inheritIO();
        pb.start().waitFor();
        LOGGER.log(DEBUG, "\t Certificate copied to {0}", out.getAbsolutePath());
    }

}
