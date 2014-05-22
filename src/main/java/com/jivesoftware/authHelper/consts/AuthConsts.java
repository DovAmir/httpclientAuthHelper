package com.jivesoftware.authHelper.consts;

import java.io.File;

public class AuthConsts {

    public static final String BROWSER_USER_AGENT_VALUE = "Mozilla/5.0 (Macintosh; " +
            "Intel Mac OS X 10_8_4) AppleWebKit/537.36 (KHTML, " +
            "like Gecko) Chrome/34.0.1847.131 Safari/537.36";
    public static final String HTTP_DEFAULT_HEADERS = "http.default-headers";
    public static final String USER_AGENT = "User-Agent";
    public static final String NEGOTIATE = "Negotiate";
    public static final String FORMS_BASED_AUTH_ACCEPTED_HEADER = "X-FORMS_BASED_AUTH_ACCEPTED";
    public static final String REALM = "java.security.krb5.realm";
    public static final String KDC = "java.security.krb5.kdc";
    public static final String USE_SUBJECT_CREDS = "javax.security.auth.useSubjectCredsOnly";
    public static final String HTTPS_SCHEMA = "https";
    public static final int HTTPS_PORT = 443;
    public static final String DEFAULT_STORE_PASSWORD = "changit";
    public static final String JRE_HOME = System.getProperties().getProperty("java.home");
    public static final String DEFAULT_TRUST_STORE_PATH =
            JRE_HOME + File.separator + "lib" + File.separator + "security" + File.separator + "cacerts";
    public static final String CONTENT_ENCODING_HEADER = "Content-Encoding";
    public static final String GZIP = "gzip";
}
