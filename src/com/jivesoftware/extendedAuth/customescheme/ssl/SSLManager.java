package com.jivesoftware.extendedAuth.customescheme.ssl;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.util.logging.Logger;

/**
 * Created with IntelliJ IDEA.
 * User: dovamir
 * Date: 4/30/14
 * Time: 3:52 PM
 * To change this template use File | Settings | File Templates.
 */
/*
   This class is responsible for returning the list of trust managers used for verifying certificates. The trust
   managers are obtained based on the trust store being used. If no trust store is specified then the default will be
   lib/security/cacerts of the JRE being used.
 */
public class SSLManager {

    private static final Logger LOG = Logger.getLogger(SSLManager.class.getName());

    private static String storeType;

    private static KeyStore trustStore;
    private static String trustStoreLocation;
    private static String trustpass;
    private static TrustManager[] trustManagers;

    private SSLManager() {
    }

    static {
        // Check the type of trust store. By default: JKS
        storeType = "jks";

        // Find the JRE home being currently used by this JVM
        String jreHome = System.getProperties().getProperty("java.home");
        // Get the truststore location
        trustStoreLocation =
                jreHome + File.separator + "lib" + File.separator + "security" + File.separator + "cacerts";
        // Get the truststore password
        trustpass = "changeit";

        // Load trusstore
        try {
            trustStore = KeyStore.getInstance(storeType);
            trustStore.load(new FileInputStream(trustStoreLocation), trustpass.toCharArray());
            // Build trust managers for the loaded trust store
            TrustManagerFactory trustFactory = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustFactory.init(trustStore);
            trustManagers = trustFactory.getTrustManagers();

            LOG.info("Loaded TrustStore from '" + trustStoreLocation + "' store type " + storeType);
        } catch (Exception e) {
            LOG.log(java.util.logging.Level.SEVERE,
                    "SSLConfig startup problem.\n" + "  storeType: [" + storeType + "]\n" + "  trustStoreLocation: ["
                            + trustStoreLocation + "]\n" + "  c2sTrustPass: [" + trustpass + "]", e);
            trustStore = null;
        }
    }

    /**
     * Get the Trust Store.
     *
     * @return the Trust Store
     */
    public static KeyStore getTrustStore() throws IOException {
        if (trustStore == null) {
            throw new IOException();
        }
        return trustStore;
    }

    /**
     * Returns the trust managers to use for verifying certificates. The trust managers will
     * rely on the certificates found on the trust store being used by this class.
     *
     * @return the trust managers to use for verifying certificates.
     */
    public static TrustManager[] getTrustManagers() {
        return trustManagers;
    }
}
