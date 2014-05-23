package com.jivesoftware.authHelper.utils;

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
import java.security.Provider;
import java.security.Security;
import java.util.Comparator;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * Created with IntelliJ IDEA.
 * User: dovamir
 * Date: 4/29/14
 * Time: 7:21 PM
 *
 *
 * to make these tests relevant , they test real URLs on the web. Of course the drawback
 * is that if these urls change the tests will fail .
 * the tests to NTLM, kerberos and proxy have been tested internally but are not fully implemented here
 * because I could not find stable and publically available endpoints to test.
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
        CredentialsUtils.setBasicAuthCredentials(client, new UsernamePasswordCredentials("test", "test"));
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
        SSLUtils.trustAllSSLCertificates();
        int respose2 = executeRequestReturnStatus(url);
        assertEquals("Should return a 200 response", 200, respose2);
    }

    @Test()
    public void testSSLTrustAlltoValidCert() throws IOException {

        String url = "https://google.com/"; //invalid certificate
        SSLUtils.trustAllSSLCertificates();
        int respose1 = executeRequestReturnStatus(url);
        assertEquals("Should return a 200 response", 200, respose1);

    }

    @Test()
    public void testSSLTrustAlltoInvalidNameCert() throws IOException {
        String url = "https://example.com/"; //invalid certificate
        SSLUtils.trustAllSSLCertificates();
        int respose1 = executeRequestReturnStatus(url);
        assertEquals("Should return a 200 response", 200, respose1);
    }


    @Test()
    public void testSSLWithBrowserUserAgent() throws IOException {
        String url = "https://testssl.disig.sk"; //expired certificate
        SSLUtils.trustAllSSLCertificates();

        AuthUtils.useBrowserUserAgent(client);
        int respose1 = executeRequestReturnStatus(url);
        assertEquals("Should return a 200 response", 200, respose1);

    }

    @Test()
    public void testSSLWithoutBrowserUserAgent() throws IOException {

        String url = "https://testssl.disig.sk"; //expired certificate
        SSLUtils.trustAllSSLCertificates();
        int respose1 = executeRequestReturnStatus(url);
        assertEquals("Should return a 403 response when no browser user agent provided", 403, respose1);

    }


    @Test(expected = SSLException.class)
    public void testJDKDefaultSSLtoInvalidNameCert() throws IOException, SSLException {
        String url = "https://example.com/"; //invalid certificate
        SSLUtils.trustJDKDefaultSSLCertificates();
        int respose1 = executeRequestReturnStatus(url);
        fail("should not get here");
    }


    @Test(expected = SSLException.class)
    public void testJDKDefaultSSLtoExpiredCert() throws IOException, SSLException {
        String url = "https://testssl-expire.disig.sk/"; //expired certificate
        SSLUtils.trustJDKDefaultSSLCertificates();
        String respose1 = executeRequestReturnResponseAsString(url);
        fail("should not get here");
    }


    /*
    test cryptography providers
    */
    @Test
    public void testDefaultEncryptionProviders() throws Exception {
        System.out.println("========testDefaultEncryptionProviders=======");
        Provider[] providers = Security.getProviders();
        int numservices = 0;
        System.out.println("========default Providers only=======");
        for (Provider p : providers) {
            String info = p.getInfo();
            System.out.println(p.getClass() + " - " + info);
        }
        System.out.println("========default Providers + services=======");
        for (Provider p : providers) {
            String info = p.getInfo();
            //System.out.println(p.getClass() + " - " + info);
            numservices += printServices(p);
        }
        System.out.println("total number of default providers : " + providers.length);
        System.out.println("total number of default services : " + numservices);
    }

    /*
    test cryptography providers
     */
    @Test
    public void testExtendedEncryptionProviders() throws Exception {
        System.out.println("========testExtendedEncryptionProviders=======");
        AuthUtils.addEncryptionProviders();
        Provider[] providers = Security.getProviders();
        int numservices = 0;
        System.out.println("======== Extended Providers =======");
        for (Provider p : providers) {
            String info = p.getInfo();
            System.out.println(p.getClass() + " - " + info);
        }
        System.out.println("========Extended Providers + services=======");
        for (Provider p : providers) {
            String info = p.getInfo();
            //System.out.println(p.getClass() + " - " + info);
            numservices += printServices(p);
        }
        System.out.println("total number of providers : " + providers.length);
        System.out.println("total number of services : " + numservices);
    }




    /*
    Not yet implemented
     */

    @Ignore("Not yet implemented")
    public void testSSLTrustCustomStore() throws IOException {
        String url = "";
        //SSLUtils.trustCustomHTTPSCertificates();
        int respose = executeRequestReturnStatus(url);
        assertEquals("Should return a 200 response", 200, respose);
    }


    @Ignore("Not yet implemented")
    public void testKERBEROS() throws IOException {
        String url = "yourKERBEROSserver";
        SSLUtils.trustAllSSLCertificates();
        CredentialsUtils
                .setKerberosCredentials(client, new UsernamePasswordCredentials("xxx", "xxx"), "domain",
                        "kdc");
        int respose = executeRequestReturnStatus(url);
        assertEquals("Should return a 200 response", 200, respose);
    }


    @Ignore("Not yet implemented")
    public void testNTLM() throws IOException {
        String url = "yourNTLMserver";
        SSLUtils.trustAllSSLCertificates();
        CredentialsUtils.setNTLMCredentials(client, new UsernamePasswordCredentials("xxx", "xxx"), "domain");
        int respose = executeRequestReturnStatus(url);
        assertEquals("Should return a 200 response", 200, respose);
    }

    @Ignore("Not yet implemented")
    public void testUseNTLMforMixedAuth() throws IOException {
        String url = "yourCLAIMSandNTLMserver";
        SSLUtils.trustAllSSLCertificates();
        CredentialsUtils.setNTLMCredentials(client, new UsernamePasswordCredentials("xxx", "xxx"), "domain");
        int respose = executeRequestReturnStatus(url);
        assertEquals("Should return a 200 response", 200, respose);
    }

    @Ignore("Not yet implemented")
    public void testProxy() throws IOException {
        String url = "http://api.stackexchange.com/2.2/questions?site=stackoverflow";
        CredentialsUtils.setProxyHost(client, null, "88.88.88.88", 8080);
        AuthUtils.useBrowserUserAgent(client);
        int respose = executeRequestReturnStatus(url);
        assertEquals("Should return a 200 response", 200, respose);
    }


    /*
        test utils
    */

    private String executeRequestReturnResponseAsString(String url) throws IOException {
        GetMethod httpget = new GetMethod(url);
        client.executeMethod(httpget);
        return AuthUtils.getResponseAsStringAndHandleGzip(httpget);
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

    private int printServices(Provider p) {

        SortedSet<Provider.Service> services = new TreeSet(new ProviderServiceComparator());

        services.addAll(p.getServices());
        for (Provider.Service service : services) {

            String algo = service.getAlgorithm();

            //System.out.println("==> Service: " + service.getType() + " - " + algo);

        }
        return services.size();

    }

    /**
     * This is to sort the various Services to make it easier on the eyes...
     */

    private class ProviderServiceComparator implements Comparator<Provider.Service> {
        @Override
        public int compare(Provider.Service object1, Provider.Service object2) {

            String s1 = object1.getType() + object1.getAlgorithm();

            String s2 = object2.getType() + object2.getAlgorithm();


            return s1.compareTo(s2);

        }
    }
}
