package com.jivesoftware.authHelper.utils;


import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpState;
import org.apache.commons.httpclient.NTCredentials;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.commons.httpclient.auth.AuthPolicy;
import org.apache.commons.httpclient.auth.AuthScope;

import java.net.Inet4Address;
import java.util.ArrayList;
import java.util.logging.Logger;

import static com.jivesoftware.authHelper.consts.AuthConsts.*;

/**
 * Created with IntelliJ IDEA.
 * User: dovamir
 * Date: 4/29/14
 * Time: 7:21 PM
 * To change this template use File | Settings | File Templates.
 */
public class CredentialsUtils {
    private static Logger logger = Logger.getLogger(CredentialsUtils.class.getName());
    private static boolean registeredNTLM;
    private static boolean registeredCLAIMS;
    private static boolean registeredKERBEROS;

    /*
    handle basic authentication with the provided creds
     */
    public static void setBasicAuthCredentials(HttpClient httpClient,
                                               UsernamePasswordCredentials credentials) {
        httpClient.getState().setCredentials(
                new AuthScope(AuthScope.ANY_HOST, AuthScope.ANY_PORT), credentials);

    }

    /*
    handle NTLMv1 and\or NTLMv2 authentication with the provided creds
    see http://www.websense.com/support/article/kbarticle/How-do-I-Check-NTLM-Version-for-XID-Compatibility
    for NTLM docs
    */
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

    /*
    handle KERBEROS authentication with provided creds
    */
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
            logger.log(java.util.logging.Level.SEVERE, message, e);
        }
        try {
            logger.fine("attempting to create KERBEROS using apache http client3");
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
            logger.log(java.util.logging.Level.SEVERE, message, e);

        }


    }

    /*
    make requests go through proxy with or without basic auth creds
     */
    public static void setProxyHost(HttpClient httpClient, UsernamePasswordCredentials proxyCredentials,
                                    String proxyHost, int proxyPort) {

        if (proxyHost != null && !proxyHost.isEmpty()) {
            httpClient.getHostConfiguration().setProxy(proxyHost, proxyPort);
            if (proxyCredentials != null) {
                HttpState state = new HttpState();
                state.setProxyCredentials(new AuthScope(proxyHost, proxyPort), proxyCredentials);
                httpClient.setState(state);
            }
        }
    }


    ///////private methods

    private static void initNTLMv2() {
        if (!registeredNTLM) {
            try {
                logger.info(" adding NTLMv2 based   authentication schema for HttpClient");
                AuthPolicy.registerAuthScheme(AuthPolicy.NTLM,
                        com.jivesoftware.authHelper.customescheme.ntlm2.CustomNTLM2Scheme.class);
                registeredNTLM = true;
            } catch (Throwable e) {
                logger.log(java.util.logging.Level.SEVERE,
                        "Could not add NTLM based on JCIFS authentication schema for HttpClient.", e);

            }
        }
    }

    private static void initKERBEROS(HttpClient httpClient) {
        if (!registeredKERBEROS) {
            try {
                logger.info("Globally adding KERBEROS ");
                System.setProperty(USE_SUBJECT_CREDS, "false");

                AuthPolicy.registerAuthScheme(NEGOTIATE,
                        com.jivesoftware.authHelper.customescheme.negotiate.CustomNegotiateScheme.class);
                registeredKERBEROS = true;
            } catch (Throwable e) {
                logger.log(java.util.logging.Level.SEVERE, "Could not add KERBEROS  for HttpClient.", e);
            }

        }
    }

}
