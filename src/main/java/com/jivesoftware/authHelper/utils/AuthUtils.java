package com.jivesoftware.authHelper.utils;

import com.jivesoftware.authHelper.consts.AuthConsts;
import com.jivesoftware.authHelper.consts.SecurityLogType;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.commons.httpclient.params.HttpClientParams;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.util.HashSet;
import java.util.Scanner;
import java.util.logging.Logger;
import java.util.zip.GZIPInputStream;

import static com.jivesoftware.authHelper.consts.AuthConsts.*;

/**
 * Created with IntelliJ IDEA.
 * User: dovamir
 * Date: 4/29/14
 * Time: 7:21 PM
 * To change this template use File | Settings | File Templates.
 */
public class AuthUtils {
    private static Logger logger = Logger.getLogger(AuthUtils.class.getName());

    private static boolean registeredCLAIMS;


    /*
    add to java.security.Provider encryption algorithms that might not be
    available in your default JVM settings
     */
    public static void addEncryptionProviders() {
        try {
            java.security.Provider secProvider1 = (java.security.Provider) Class
                    .forName("com.sun.crypto.provider.SunJCE").newInstance();
            Security.addProvider(secProvider1);
        } catch (Exception e) {
        }
        try {
            java.security.Provider secProvider2 = (java.security.Provider) Class
                    .forName("com.ncipher.provider.km.nCipherKM").newInstance();
            Security.addProvider(secProvider2);
        } catch (Exception e) {
        }
        try {
            java.security.Provider secProvider3 = (java.security.Provider) Class
                    .forName("com.ibm.crypto.provider.IBMJCE").newInstance();
            Security.addProvider(secProvider3);
        } catch (Exception e) {
        }
        try {
            java.security.Provider secProvider4 = (java.security.Provider) Class
                    .forName("sun.security.rsa.SunRsaSign").newInstance();
            Security.addProvider(secProvider4);
        } catch (Exception e) {
        }
        try {
            Security.addProvider(new BouncyCastleProvider());
        } catch (Exception e) {
        }
    }

    /*
    enable\disable logging for different security mechanisms
     */
    public static void securityLogging(SecurityLogType logType, boolean enable) {
        String value = String.valueOf(enable);
        if (enable && logType.equals(SecurityLogType.ALL) || logType.equals(SecurityLogType.SSL)) {
            value = logType.toString().toLowerCase();
        }
        System.setProperty(logType.getLogtype(), value);
    }


    /*
    return the response as a String, if the response is a GZIPed stream, it will be ungizped
    */
    public static String getResponseAsStringAndHandleGzip(HttpMethodBase httpget) throws IOException {
        Header contentEncodingHeader = httpget.getResponseHeader(CONTENT_ENCODING_HEADER);
        InputStream stream = httpget.getResponseBodyAsStream();
        if (contentEncodingHeader != null && contentEncodingHeader.getValue().equalsIgnoreCase(GZIP)) {
            stream = new GZIPInputStream(stream);
        }
        String inputStreamString = new Scanner(stream, "UTF-8").useDelimiter("\\A").next();
        return inputStreamString;
    }


    /*
     Accessing mixed authentication windows Client using windows (ntlm) authentication.
     The mixed authentication can be for example NTLM and Forms based
     http://buyevich.blogspot.co.il/2011/03/accessing-mixed-authentication-web-app.html
     */
    public static void useNTLMforMixedAuth(HttpClient httpClient) {
        if (!registeredCLAIMS) {
            logger.info(" adding header to avoid forms based auth");
            addDefaultHeader(httpClient, false, FORMS_BASED_AUTH_ACCEPTED_HEADER, "f");
            registeredCLAIMS = true;
        }
    }

    /*
    make all requests with a user agent of a browser, some endpoints serve only requests with a browser user agent
     */
    public static void useBrowserUserAgent(HttpClient httpClient) {
        logger.info(" adding user agent of a browser");
        addDefaultHeader(httpClient, false, USER_AGENT,
                AuthConsts.BROWSER_USER_AGENT_VALUE);
    }

    /*
    pring all headers of a response for debugging
    */
    public static Header[] printResponseHeaders(HttpMethodBase httpget) throws IOException {
        System.out.println("Printing Response Header...\n");

        Header[] headers = httpget.getResponseHeaders();
        for (Header header : headers) {
            System.out.println("Key : " + header.getName()
                    + " ,Value : " + header.getValue());

        }
        return headers;
    }


    /*
    utility method to add/remove headers that will be sent on every request from the httpclient object
     */
    public static void addDefaultHeader(HttpClient httpClient, boolean removeHeader, String headerName,
                                        String headervalue) {
        HttpClientParams clientParams = httpClient.getParams();
        HashSet<Header> headerSet = (HashSet<Header>) clientParams.getParameter(HTTP_DEFAULT_HEADERS);
        if (headerSet == null) {
            headerSet = new HashSet<Header>();
            clientParams.setParameter(HTTP_DEFAULT_HEADERS, headerSet);
        }
        Header header1 = new Header(headerName, headervalue);
        if (!headerSet.contains(header1) && !removeHeader) {
            headerSet.add(header1);
        } else if (headerSet.contains(header1) && removeHeader) {
            headerSet.remove(header1);
        }
    }


}
