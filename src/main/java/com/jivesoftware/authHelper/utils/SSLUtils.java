package com.jivesoftware.authHelper.utils;


import org.apache.commons.httpclient.contrib.ssl.AuthSSLProtocolSocketFactory;
import org.apache.commons.httpclient.contrib.ssl.EasySSLProtocolSocketFactory;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;


import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.util.logging.Logger;

import static com.jivesoftware.authHelper.consts.AuthConsts.*;

/**
 * Created with IntelliJ IDEA.
 * User: dovamir
 * Date: 4/29/14
 * Time: 7:21 PM
 * To change this template use File | Settings | File Templates.
 */
public class SSLUtils {
    private static Logger logger = Logger.getLogger(SSLUtils.class.getName());
    private static boolean registeredHTTPStrustAll;
    private static boolean registeredHTTPStrustKeyStore;
    //System.setProperty("jsse.enableSNIExtension", "false");

    /*
      creats SSL Sockets that accepts all certificates including expired and self-signed certificates
      warning : might be insecure , use for testing
     */
    public static void trustAllSSLCertificates() {

        if (!registeredHTTPStrustAll) {
            try {
                logger.info("started registering https to trust all certificates");
                ProtocolSocketFactory myHTTPSProtocol = new EasySSLProtocolSocketFactory();
                Protocol.registerProtocol(HTTPS_SCHEMA,
                        new Protocol(HTTPS_SCHEMA, myHTTPSProtocol, HTTPS_PORT));
                logger.info("finished registering https to trust all certificates");
                registeredHTTPStrustAll = true;
            } catch (GeneralSecurityException e) {
                logger.log(java.util.logging.Level.SEVERE, "Failed to register https protocol .", e);
            } catch (IOException e) {
                logger.log(java.util.logging.Level.SEVERE, "Failed to register https protocol .", e);
            }

        }
    }

    public static void trustJDKDefaultSSLCertificates() {
        trustCustomHTTPSCertificates(null, null, null, null,
                HTTPS_PORT); //DEFAULT_TRUST_STORE_PATH, DEFAULT_STORE_PASSWORD);
    }

    public static void trustCustomHTTPSCertificates(final String pathToKeyStore,
                                                    final String pathToTruststore) {
        trustCustomHTTPSCertificates(pathToKeyStore, DEFAULT_STORE_PASSWORD, pathToTruststore, DEFAULT_STORE_PASSWORD,
                HTTPS_PORT);
    }

    /*
      * optionally enforce mutual client/server authentication.
      *    validate the identity of the HTTPS server against a list of trusted certificates
      *    only trusts the public certificates you provide to its constructor
      * @param keystoreUrl        URL of the keystore file. May be <tt>null</tt> if HTTPS client
      *                           authentication is not to be used.
      * @param keystorePassword   Password to unlock the keystore. IMPORTANT: this implementation
      *                           assumes that the same password is used to protect the key and the keystore itself.
      * @param truststoreUrl      URL of the truststore file. May be <tt>null</tt> if HTTPS server
      *                           authentication is not to be used.
      * @param truststorePassword Password to unlock the truststore.
     */
    public static void trustCustomHTTPSCertificates(final String pathToKeyStore,
                                                    final String keystorePassword,
                                                    final String pathToTruststore,
                                                    final String truststorePassword,
                                                    final Integer port) {

        if (!registeredHTTPStrustKeyStore) {
            try {
                logger.info("started registering https protocol ");
                URL urlToTruststore =
                        pathToTruststore == null || pathToTruststore.isEmpty() ? null : new URL(pathToTruststore);
                URL urlToKeyStore = pathToKeyStore == null || pathToKeyStore.isEmpty() ? null : new URL(pathToKeyStore);

                ProtocolSocketFactory socketFactory =
                        new AuthSSLProtocolSocketFactory(urlToTruststore, truststorePassword, urlToKeyStore,
                                keystorePassword);
                Protocol myHTTPSProtocol = new Protocol(HTTPS_SCHEMA, socketFactory, port == null ? HTTPS_PORT : port);
                Protocol.registerProtocol(HTTPS_SCHEMA, myHTTPSProtocol);
                registeredHTTPStrustKeyStore = true;
                logger.info("finished registering https protocol ");
                //httpClient.getHostConfiguration().setHost(url.getHost(), HTTPS_PORT, myhttps);
            } catch (GeneralSecurityException e) {
                logger.log(java.util.logging.Level.SEVERE, "Failed to register https protocol .", e);
            } catch (IOException e) {
                logger.log(java.util.logging.Level.SEVERE, "Failed to register https protocol .", e);
            } catch (Exception e) {
                logger.log(java.util.logging.Level.SEVERE, "Failed to register https protocol .", e);
            }

        }
    }



}
