package io.smallrye.certs.ca;

import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.INFO;

import java.io.File;
import java.nio.file.Files;

import com.dd.plist.*;

/**
 * Utility class to install the CA certificate on a Mac.
 */
public class MacCAInstaller {

    static System.Logger LOGGER = System.getLogger(CaGenerator.class.getName());

    public static void installCAOnMac(String cn, File ca) throws Exception {
        LOGGER.log(INFO,
                "🔥 Installing CA certificate (issuer: {0}) into your operating system keychain. Your admin password may be asked.",
                cn);
        ProcessBuilder pb = new ProcessBuilder("sudo", "security", "-v", "add-trusted-cert", "-d", "-r", "trustRoot", "-k",
                "/Library/Keychains/System.keychain", ca.getAbsolutePath());
        pb.inheritIO();
        pb.start().waitFor();
        LOGGER.log(DEBUG, "\t Certificate added to the keychain");

        var tmp = new File("trust-settings.plist");
        pb = new ProcessBuilder("sudo", "security", "trust-settings-export", "-d", tmp.getAbsolutePath());
        pb.inheritIO();
        pb.start().waitFor();
        LOGGER.log(DEBUG, "\t Trust settings exported to {0}", tmp.getAbsolutePath());

        pb = new ProcessBuilder("sudo", "chown", System.getProperty("user.name"), tmp.getAbsolutePath());
        pb.inheritIO();
        pb.start().waitFor();

        updateCertificateTrustSettings(cn, tmp);

        LOGGER.log(DEBUG, "\t Trust settings updated");

        pb = new ProcessBuilder("sudo", "security", "trust-settings-import", "-d", tmp.getAbsolutePath());
        pb.inheritIO();
        pb.start().waitFor();

        LOGGER.log(DEBUG, "\t Trust settings imported");
    }

    private static void updateCertificateTrustSettings(String cn, File plist) throws Exception {
        var content = Files.readString(plist.toPath());
        NSDictionary main = (NSDictionary) PropertyListParser.parse(content.getBytes());
        NSDictionary certs = (NSDictionary) main.get("trustList");

        boolean found = false;
        for (int i = 0; i < certs.allKeys().length; i++) {
            String k = certs.allKeys()[i];
            NSDictionary value = (NSDictionary) certs.objectForKey(k);
            NSData data = (NSData) value.get("issuerName");
            String v = data.getBase64EncodedData();
            byte[] decodedBytes = java.util.Base64.getDecoder().decode(v.getBytes());
            String in = new String(decodedBytes);
            if (in.contains(cn)) {
                LOGGER.log(DEBUG, "found ca certificate in plist");
                found = true;
                /*
                 * <dict>
                 * <key>kSecTrustSettingsAllowedError</key>
                 * <integer>-2147408896</integer>
                 * <key>kSecTrustSettingsPolicy</key>
                 * <data>
                 * KoZIhvdjZAED
                 * </data>
                 * <key>kSecTrustSettingsPolicyName</key>
                 * <string>sslServer</string>
                 * <key>kSecTrustSettingsResult</key>
                 * <integer>2</integer>
                 * </dict>
                 * <dict>
                 * <key>kSecTrustSettingsAllowedError</key>
                 * <integer>-2147409654</integer>
                 * <key>kSecTrustSettingsPolicy</key>
                 * <data>
                 * KoZIhvdjZAEC
                 * </data>
                 * <key>kSecTrustSettingsPolicyName</key>
                 * <string>basicX509</string>
                 * <key>kSecTrustSettingsResult</key>
                 * <integer>2</integer>
                 * </dict>
                 */
                NSArray settings = new NSArray(2);
                NSDictionary dict0 = new NSDictionary();
                NSDictionary dict1 = new NSDictionary();
                dict0.put("kSecTrustSettingsPolicy", new NSData("KoZIhvdjZAED"));
                dict0.put("kSecTrustSettingsPolicyName", new NSString("sslServer"));
                dict0.put("kSecTrustSettingsResult", new NSNumber(2));

                dict1.put("kSecTrustSettingsPolicy", new NSData("KoZIhvdjZAEC"));
                dict1.put("kSecTrustSettingsPolicyName", new NSString("basicX509"));
                dict1.put("kSecTrustSettingsResult", new NSNumber(2));

                settings.setValue(0, dict0);
                settings.setValue(1, dict1);

                value.put("trustSettings", settings);
            }
        }
        if (!found) {
            LOGGER.log(INFO, "\uD83D\uDEAB CA certificate not found in plist");
        }
        Files.writeString(plist.toPath(), main.toXMLPropertyList());
    }
}
