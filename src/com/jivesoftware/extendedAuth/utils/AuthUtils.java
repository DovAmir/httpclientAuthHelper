package com.jivesoftware.extendedAuth.utils;

import com.jivesoftware.extendedAuth.customescheme.negotiate.KerberosCredentials;
import java.io.File;
import java.io.IOException;
import java.net.*;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.logging.Logger;

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.NTCredentials;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.commons.httpclient.auth.AuthPolicy;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.contrib.ssl.AuthSSLProtocolSocketFactory;
import org.apache.commons.httpclient.contrib.ssl.EasySSLProtocolSocketFactory;
import org.apache.commons.httpclient.params.HttpClientParams;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;


/**
 * Created with IntelliJ IDEA.
 * User: dovamir
 * Date: 4/29/14
 * Time: 7:21 PM
 * To change this template use File | Settings | File Templates.
 */
public class AuthUtils {

    private static Logger LOG = Logger.getLogger(AuthUtils.class.getName());

    private static boolean registeredNTLM;
    private static boolean registeredCLAIMS;
    private static boolean registeredKERBEROS;
    private static boolean registeredHTTPStrustAll;
    private static boolean registeredHTTPStrustKeyStore;

    private static final String NEGOTIATE = "Negotiate";
    private static final String FORMS_BASED_AUTH_ACCEPTED_HEADER = "X-FORMS_BASED_AUTH_ACCEPTED";
    private static final String REALM = "java.security.krb5.realm";
    private static final String KDC = "java.security.krb5.kdc";
    private static final String USE_SUBJECT_CREDS = "javax.security.auth.useSubjectCredsOnly";
    private static final String HTTPS_SCHEMA = "https";
    private static final int HTTPS_PORT = 443;
    private static final String DEFAULT_STORE_PASSWORD = "changit";
    private static final String JRE_HOME = System.getProperties().getProperty("java.home");
    private static final String DEFAULT_TRUST_STORE_PATH =
            JRE_HOME + File.separator + "lib" + File.separator + "security" + File.separator + "cacerts";


    private void setNTLMCredentials(HttpClient httpClient, String url, NTCredentials credentials) {
        initNTLMv2();

        String localHostName;
        try {
            localHostName = Inet4Address.getLocalHost().getHostName();
        } catch (UnknownHostException e) {
            localHostName = "";
        } catch (Exception e) {
            localHostName = "";
        }

        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            throw new RuntimeException(
                    "Could not parse  URL: " + url);
        }

        int port = uri.getPort();
        AuthScope authscope;
        if (port == -1) {
            authscope = new AuthScope(uri.getHost(), AuthScope.ANY_PORT);
        } else {
            authscope = new AuthScope(uri.getHost(), port);
        }

        httpClient.getState().setCredentials(
                authscope,
                new NTCredentials(
                        credentials.getUserName(),
                        credentials.getPassword(),
                        localHostName, credentials.getDomain()));
    }

    /*
     Accessing mixed authentication windows Client using windows (ntlm) authentication.
     The mixed authentication can be for example NTLM and Forms based
     http://buyevich.blogspot.co.il/2011/03/accessing-mixed-authentication-web-app.html
     */

    private void initUseNTLMforMixedAuth(HttpClient httpClient) {
        if (!registeredCLAIMS) {
            LOG.info(" adding header to avoid forms based auth");
            HttpClientParams clientParams = httpClient.getParams();
            HashSet<Header> headerSet = (HashSet<Header>) clientParams.getParameter("http.default-headers");
            Header header = new Header(FORMS_BASED_AUTH_ACCEPTED_HEADER, "f");
            headerSet.add(header);
            registeredCLAIMS = true;
        }
    }

    private void initNTLMv2() {
        if (!registeredNTLM) {
            try {
                LOG.info(" adding NTLMv2 based   authentication schema for HttpClient");
                AuthPolicy.registerAuthScheme(AuthPolicy.NTLM,
                        com.jivesoftware.extendedAuth.customescheme.ntlm2.CustomNTLM2Scheme.class);
                registeredNTLM = true;
            } catch (Throwable e) {
                LOG.log(java.util.logging.Level.SEVERE,
                        "Could not add NTLM based on JCIFS authentication schema for HttpClient.", e);

            }
        }
    }

    private void initKERBEROS(HttpClient httpClient) {
        if (!registeredKERBEROS) {
            try {
                LOG.info("Globally adding KERBEROS ");
                System.setProperty(USE_SUBJECT_CREDS, "false");

                AuthPolicy.registerAuthScheme(NEGOTIATE,
                        com.jivesoftware.extendedAuth.customescheme.negotiate.CustomNegotiateScheme.class);
                registeredKERBEROS = true;
            } catch (Throwable e) {
                LOG.log(java.util.logging.Level.SEVERE, "Could not add KERBEROS  for HttpClient.", e);
            }

        }
    }


    private void setKERBEROSCredentials(HttpClient httpClient, String url,
                                        KerberosCredentials kerberosCredentials) {
        try {
            //set the login scheme
            initKERBEROS(httpClient);
            System.setProperty(REALM, kerberosCredentials.getDomain().toUpperCase());
            String kdc = kerberosCredentials.getDomain();
            if (kerberosCredentials.getKdc() != null) {
                kdc = kerberosCredentials.getKdc().isEmpty() ? kerberosCredentials.getDomain().toUpperCase()
                        : kerberosCredentials.getKdc();
            }
            System.setProperty(KDC, kdc);
        } catch (Exception e) {
            String message = "error  in initKERBEROSIfNeeded";
            LOG.log(java.util.logging.Level.SEVERE, message, e);
        }
        try {
            System.err.println("attempting to create KERBEROS using apache http client3");
            ArrayList schemes = new ArrayList();
            schemes.add(NEGOTIATE);
            schemes.add(AuthPolicy.BASIC); //to support basic auth proxy on the way
            httpClient.getParams().setParameter(AuthPolicy.AUTH_SCHEME_PRIORITY, schemes);
            AuthScope authscope = new AuthScope(null, AuthScope.ANY_PORT, null);
            UsernamePasswordCredentials useJassCreds = new UsernamePasswordCredentials(
                    kerberosCredentials.getUserName(), kerberosCredentials.getPassword());
            httpClient.getState().setCredentials(
                    authscope,
                    useJassCreds);
        } catch (Exception e) {
            String message = "Can not create And Authenticate setKERBEROSCredentials";
            LOG.log(java.util.logging.Level.SEVERE, message, e);

        }


    }

    /*
      creats SSL Sockets that accepts all certificates including expired and self-signed certificates
      warning : might be insecure
     */
    private void initHTTPStrustAll(final Integer port) {

        if (!registeredHTTPStrustAll) {
            try {
                LOG.info("started registering https to trust all certificates");
                ProtocolSocketFactory myHTTPSProtocol = new EasySSLProtocolSocketFactory();
                Protocol.registerProtocol(HTTPS_SCHEMA,
                        new Protocol(HTTPS_SCHEMA, myHTTPSProtocol, port == null ? HTTPS_PORT : port));
                LOG.info("finished registering https to trust all certificates");
                registeredHTTPStrustAll = true;
            } catch (GeneralSecurityException e) {
                LOG.log(java.util.logging.Level.SEVERE, "Failed to register https protocol .", e);
            } catch (IOException e) {
                LOG.log(java.util.logging.Level.SEVERE, "Failed to register https protocol .", e);
            }

        }
    }

    private void initHTTPSdefault() {
        initHTTPSkeysWithPass(null, null, null, null, HTTPS_PORT); //DEFAULT_TRUST_STORE_PATH, DEFAULT_STORE_PASSWORD);
    }

    private void initHTTPSkeys(final String pathToKeyStore,
                               final String pathToTruststore) {
        initHTTPSkeysWithPass(pathToKeyStore, DEFAULT_STORE_PASSWORD, pathToTruststore, DEFAULT_STORE_PASSWORD,
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
    private void initHTTPSkeysWithPass(final String pathToKeyStore,
                                       final String keystorePassword,
                                       final String pathToTruststore,
                                       final String truststorePassword,
                                       final Integer port) {

        if (!registeredHTTPStrustKeyStore) {
            try {
                LOG.info("started registering https protocol ");
                URL urlToTruststore =
                        pathToTruststore == null || pathToTruststore.isEmpty() ? null : new URL(pathToTruststore);
                URL urlToKeyStore = pathToKeyStore == null || pathToKeyStore.isEmpty() ? null : new URL(pathToKeyStore);

                ProtocolSocketFactory socketFactory =
                        new AuthSSLProtocolSocketFactory(urlToTruststore, truststorePassword, urlToKeyStore,
                                keystorePassword);
                Protocol myHTTPSProtocol = new Protocol(HTTPS_SCHEMA, socketFactory, port == null ? HTTPS_PORT : port);
                Protocol.registerProtocol(HTTPS_SCHEMA, myHTTPSProtocol);
                registeredHTTPStrustKeyStore = true;
                LOG.info("finished registering https protocol ");
                //httpClient.getHostConfiguration().setHost(url.getHost(), HTTPS_PORT, myhttps);
            } catch (GeneralSecurityException e) {
                LOG.log(java.util.logging.Level.SEVERE, "Failed to register https protocol .", e);
            } catch (IOException e) {
                LOG.log(java.util.logging.Level.SEVERE, "Failed to register https protocol .", e);
            } catch (Exception e) {
                LOG.log(java.util.logging.Level.SEVERE, "Failed to register https protocol .", e);
            }

        }
    }


}
