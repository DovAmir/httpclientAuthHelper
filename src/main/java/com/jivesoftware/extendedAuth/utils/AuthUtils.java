package com.jivesoftware.extendedAuth.utils;

import org.apache.commons.httpclient.*;
import org.apache.commons.httpclient.auth.AuthPolicy;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.contrib.ssl.AuthSSLProtocolSocketFactory;
import org.apache.commons.httpclient.contrib.ssl.EasySSLProtocolSocketFactory;
import org.apache.commons.httpclient.params.HttpClientParams;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.Inet4Address;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.logging.Logger;
import java.util.zip.GZIPInputStream;
 import static com.jivesoftware.extendedAuth.utils.AuthConsts.*;

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
    //System.setProperty("jsse.enableSNIExtension", "false");


    public static void securityLogging(SecurityLogType logType, boolean enable) {
        String value = String.valueOf(enable);
        if (enable && logType.equals(SecurityLogType.ALL) || logType.equals(SecurityLogType.SSL)) {
            value = logType.toString().toLowerCase();
        }
        System.setProperty(logType.getLogtype(), value);
    }


    public static InputStream getStreamResponseAndHandleGzip(HttpMethodBase httpget) throws IOException {
        Header contentEncodingHeader = httpget.getResponseHeader(CONTENT_ENCODING_HEADER);
        InputStream stream = httpget.getResponseBodyAsStream();
        if (contentEncodingHeader != null && contentEncodingHeader.getValue().equalsIgnoreCase(GZIP)) {
            stream = new GZIPInputStream(stream);
        }
        return stream;
    }

    public static void setBasicAuthCredentials(HttpClient httpClient,
                                               UsernamePasswordCredentials credentials) {
        httpClient.getState().setCredentials(
                new AuthScope(AuthScope.ANY_HOST, AuthScope.ANY_PORT), credentials);

    }


    // http://www.websense.com/support/article/kbarticle/How-do-I-Check-NTLM-Version-for-XID-Compatibility
    public static void setNTLMCredentials(HttpClient httpClient, UsernamePasswordCredentials credentials,
                                          String domain) {
        initNTLMv2();

        String localHostName;
        try {
            localHostName = Inet4Address.getLocalHost().getHostName();
        } catch (Exception e) {
            localHostName = "";
        }

        AuthScope authscope = new AuthScope(AuthScope.ANY_HOST, AuthScope.ANY_PORT);
        httpClient.getState().setCredentials(
                authscope,
                new NTCredentials(
                        credentials.getUserName(),
                        credentials.getPassword(),
                        localHostName, domain));
    }


    public static void setKerberosCredentials(HttpClient httpClient,
                                              UsernamePasswordCredentials credentials, String domain, String kdc) {
        try {
            //set the login scheme
            initKERBEROS(httpClient);

            System.setProperty(REALM, domain.toUpperCase());
            kdc = (kdc == null || kdc.isEmpty()) ? domain.toUpperCase() : kdc;
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
            AuthScope authscope = new AuthScope(AuthScope.ANY_HOST, AuthScope.ANY_PORT, null);

            httpClient.getState().setCredentials(
                    authscope,
                    credentials);
        } catch (Exception e) {
            String message = "Can not create And Authenticate setKERBEROSCredentials";
            LOG.log(java.util.logging.Level.SEVERE, message, e);

        }


    }


    public static void addDefaultHeader(SecurityLogType logType, boolean enable) {
        String value = String.valueOf(enable);
        if (enable && logType.equals(SecurityLogType.ALL) || logType.equals(SecurityLogType.SSL)) {
            value = logType.toString().toLowerCase();
        }
        System.setProperty(logType.getLogtype(), value);
    }

        /*
     Accessing mixed authentication windows Client using windows (ntlm) authentication.
     The mixed authentication can be for example NTLM and Forms based
     http://buyevich.blogspot.co.il/2011/03/accessing-mixed-authentication-web-app.html
     */

    public static void useNTLMforMixedAuth(HttpClient httpClient) {
        if (!registeredCLAIMS) {
            LOG.info(" adding header to avoid forms based auth");
            addDefaultHeader(httpClient, false, FORMS_BASED_AUTH_ACCEPTED_HEADER, "f");
            registeredCLAIMS = true;
        }
    }

    public static void impersonateBrowserUserAgent(HttpClient httpClient) {
        LOG.info(" adding user agent of a browser");
        addDefaultHeader(httpClient, false, USER_AGENT,
                AuthConsts.BROWSER_USER_AGENT_VALUE);
    }

    private static void addDefaultHeader(HttpClient httpClient, boolean removeHeader, String headerName,
                                         String headervalue) {
        HttpClientParams clientParams = httpClient.getParams();
        HashSet<Header> headerSet = (HashSet<Header>) clientParams.getParameter(HTTP_DEFAULT_HEADERS);
        if (!headerSet.contains(headerName) && !removeHeader) {
            Header header1 = new Header(headerName, headervalue);
            headerSet.add(header1);
        } else if (headerSet.contains(headerName) && removeHeader) {
            headerSet.remove(headerName);
        }
    }

    private static void initNTLMv2() {
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

    private static void initKERBEROS(HttpClient httpClient) {
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


    /*
      creats SSL Sockets that accepts all certificates including expired and self-signed certificates
      warning : might be insecure
     */
    public static void initHTTPStrustAll() {

        if (!registeredHTTPStrustAll) {
            try {
                LOG.info("started registering https to trust all certificates");
                ProtocolSocketFactory myHTTPSProtocol = new EasySSLProtocolSocketFactory();
                Protocol.registerProtocol(HTTPS_SCHEMA,
                        new Protocol(HTTPS_SCHEMA, myHTTPSProtocol, HTTPS_PORT));
                LOG.info("finished registering https to trust all certificates");
                registeredHTTPStrustAll = true;
            } catch (GeneralSecurityException e) {
                LOG.log(java.util.logging.Level.SEVERE, "Failed to register https protocol .", e);
            } catch (IOException e) {
                LOG.log(java.util.logging.Level.SEVERE, "Failed to register https protocol .", e);
            }

        }
    }

    public static void initHTTPSdefault() {
        initHTTPSkeysWithPass(null, null, null, null, HTTPS_PORT); //DEFAULT_TRUST_STORE_PATH, DEFAULT_STORE_PASSWORD);
    }

    public static void initHTTPSkeys(final String pathToKeyStore,
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
    public static void initHTTPSkeysWithPass(final String pathToKeyStore,
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
