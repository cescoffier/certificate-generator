package me.escoffier.certs.ca;

import java.io.File;

/**
 * A utility to install the CA certificate on Windows.
 */
public class WindowsCAInstaller {
    static System.Logger LOGGER = System.getLogger(CaGenerator.class.getName());


    public static void installCAOnWindows(String cn, File ca) throws Exception {
        LOGGER.log(System.Logger.Level.INFO, "🔥 Installing CA certificate (issuer: {0}) into your operating system keychain. Make sure your are in a privileged (`run with administrator`) terminal.", cn);
        ProcessBuilder pb = new ProcessBuilder("certutil", "-addstore", "-v", "-f", "-user", "Root", ca.getAbsolutePath());
        pb.inheritIO();
        int res = pb.start().waitFor();

        if (res != 0) {
            LOGGER.log(System.Logger.Level.ERROR, "❌ Unable to install the CA certificate into the keychain. Please run: `certutil -addstore -v -f -user Root " + ca.getAbsolutePath() + "` in a privileged terminal.");
            return;
        }

        LOGGER.log(System.Logger.Level.DEBUG, "\t Certificate added to the keychain");
    }

}
