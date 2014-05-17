package com.jivesoftware.extendedAuth.utils;

import junit.framework.TestCase;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.commons.httpclient.methods.GetMethod;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.junit.runners.MethodSorters;

import javax.net.ssl.SSLException;
import java.io.IOException;

/**
 * Created with IntelliJ IDEA.
 * User: dovamir
 * Date: 4/29/14
 * Time: 7:21 PM
 * To change this template use File | Settings | File Templates.
 */
@RunWith(JUnit4.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AuthUtilsTest extends TestCase {
    HttpClient client;


    @Before
    public void setUp() throws Exception {
        super.setUp();
        client = new HttpClient();
    }

    @Override
    protected void tearDown() throws Exception {
        client = null;
        super.tearDown();
    }

    @Test
    public void testGzipedResponseAsJson() throws IOException {
        String url = "http://api.stackexchange.com/2.2/questions?site=stackoverflow";
        String respose = executeRequestReturnResponseAsString(url);
        assertNotNull("Should return a response", respose);
        assertTrue("response should be json ", isJSONValid(respose));
    }

    @Test
    public void testBasicAuth() throws IOException {
        String url = "http://browserspy.dk/password-ok.php";
        int respose1 = executeRequestReturnStatus(url);
        assertEquals("Should return a 401 response", 401, respose1);
        AuthUtils.setBasicAuthCredentials(client, new UsernamePasswordCredentials("test", "test"));
        int respose2 = executeRequestReturnStatus(url);
        assertEquals("Should return a 200 response", 200, respose2);
    }


    /*
    some sites to test ssl certificates:
        https://www.ssllabs.com/ssltest/
        http://www.digicert.com/help/
        http://www.sslshopper.com/ssl-checker.html
        http://testssl.disig.sk/index.en.html
     */


    @Test()
    public void testJDKDefaultSSLtoValidCert() throws IOException {

        String url = "https://www.google.com/"; //valid certificate
        AuthUtils.trustAllSSLCertificates();
        int respose2 = executeRequestReturnStatus(url);
        assertEquals("Should return a 200 response", 200, respose2);
    }

    @Test()
    public void testSSLTrustAlltoValidCert() throws IOException {

        String url = "https://google.com/"; //invalid certificate
        AuthUtils.trustAllSSLCertificates();
        int respose1 = executeRequestReturnStatus(url);
        assertEquals("Should return a 200 response", 200, respose1);

    }

    @Test()
    public void testSSLTrustAlltoInvalidNameCert() throws IOException {
        String url = "https://example.com/"; //invalid certificate
        AuthUtils.trustAllSSLCertificates();
        int respose1 = executeRequestReturnStatus(url);
        assertEquals("Should return a 200 response", 200, respose1);
    }


    @Test()
    public void testSSLWithBrowserUserAgent() throws IOException {
        String url = "https://testssl.disig.sk"; //expired certificate
        AuthUtils.trustAllSSLCertificates();

        AuthUtils.impersonateBrowserUserAgent(client);
        int respose1 = executeRequestReturnStatus(url);
        assertEquals("Should return a 200 response", 200, respose1);

    }

    @Test()
    public void testSSLWithOutBrowserUserAgent() throws IOException {

        String url = "https://testssl.disig.sk"; //expired certificate
        AuthUtils.trustAllSSLCertificates();
        int respose1 = executeRequestReturnStatus(url);
        assertEquals("Should return a 403 response when no browser user agent provided", 403, respose1);

    }


    @Test(expected = SSLException.class)
    public void testJDKDefaultSSLtoInvalidNameCert() throws IOException, SSLException {
        String url = "https://example.com/"; //invalid certificate
        AuthUtils.trustJDKDefaultSSLCertificates();
        int respose1 = executeRequestReturnStatus(url);
        fail();
    }


    @Test(expected = SSLException.class)
    public void testJDKDefaultSSLtoExpiredCert() throws IOException, SSLException {
        String url = "https://testssl-expire.disig.sk/"; //expired certificate
        AuthUtils.trustJDKDefaultSSLCertificates();
        String respose1 = executeRequestReturnResponseAsString(url);
        fail();
    }


    /*
    Not yet implemented
     */

    @Ignore("Not yet implemented")
    public void testSSLTrustCustomStore() throws IOException {
        String url = "http://api.stackexchange.com/2.2/questions?site=stackoverflow";
        int respose = executeRequestReturnStatus(url);
        assertEquals("Should return a 200 response", 200, respose);
    }


    @Ignore("Not yet implemented")
    public void testKERBEROS() throws IOException {
        String url = "https://il-qa-sp1301.qa-spc.eng.jiveland.com:443/sites/DovCollection";
        AuthUtils
                .setKerberosCredentials(client, new UsernamePasswordCredentials("hod.kashtan", "Welcome123!"), "qa-spc",
                        "qa-spc");
        int respose = executeRequestReturnStatus(url);
        assertEquals("Should return a 200 response", 200, respose);
    }


    @Ignore("Not yet implemented")
    public void testNTLM() throws IOException {
        String url = "https://il-qa-sp1301.qa-spc.eng.jiveland.com:8866/sites/DovCollection";
        AuthUtils.setNTLMCredentials(client, new UsernamePasswordCredentials("hod.kashtan", "Welcome123!"), "qa-spc");
        int respose = executeRequestReturnStatus(url);
        assertEquals("Should return a 200 response", 200, respose);
    }

    @Ignore("Not yet implemented")
    public void testUseNTLMforMixedAuth() throws IOException {
        String url = "https://il-qa-sp1301.qa-spc.eng.jiveland.com:8866/sites/DovCollection";
        AuthUtils.setNTLMCredentials(client, new UsernamePasswordCredentials("hod.kashtan", "Welcome123!"), "qa-spc");
        int respose = executeRequestReturnStatus(url);
        assertEquals("Should return a 200 response", 200, respose);
    }

    @Ignore("Not yet implemented")
    public void testProxy() throws IOException {
        String url = "http://api.stackexchange.com/2.2/questions?site=stackoverflow";
        int respose = executeRequestReturnStatus(url);
        assertEquals("Should return a 200 response", 200, respose);
    }


    /*
        test utils
    */

    private String executeRequestReturnResponseAsString(String url) throws IOException {
        GetMethod httpget = new GetMethod(url);
        client.executeMethod(httpget);
        return AuthUtils.getStreamResponseAsStringAndHandleGzip(httpget);
    }

    private int executeRequestReturnStatus(String url) throws IOException {
        GetMethod httpget = new GetMethod(url);
        client.executeMethod(httpget);
        return httpget.getStatusCode();
    }

    public static boolean isJSONValid(String test) {
        try {
            new JSONObject(test);
            return true;
        } catch (JSONException ex) {
            return false;
        }
    }
}
