# Httpclient Authentication Helper

## What is it?
A library that helps authenticate Httpclient 3  with services that use  NTLM, KERBEROS and SSL authentication.

The design goal is to be as simple as possible to use.
The library uses default configurations that apply to 99% of the use cases, so that the developer wont
have to concern himself with the details of his chosen authentication mechanism.

The main features are:

CredentialsUtils:

* support basic  authenticaion
* route request through a proxy
* support NTLM v1 and NTLMv2  (httpclient3.x does not support NTLMv2 and supports NTLMv1 only with the JCFIS package )
* support KERBEROS without the need for any external configuration files (login.conf , krb.ini )

SSLUtils:

support SSL in 3 modes-
* trust all certificates,
* trust JDK truststore (cacerts),
* trust custom truststore

AuthUtils:

vairious tools
* logging for security
* cryptography providers
* use browser user agent
* handle gzipped response
 and more ...

## How to use?

Example:
```javascript

    /*
        Example a: connect to a service on a windows iis server that is protected by NTLMv2
        and has a self signed certificate
    */
        DefaultHttpClient httpclient = new DefaultHttpClient();

        SSLUtils.trustAllSSLCertificates();
        CredentialsUtils.setNTLMCredentials(client, new UsernamePasswordCredentials("xxx", "xxx"), "mydomain");

        client.executeMethod(httpget);

    /*
        Example b: connect to a service  that is protected by KERBEROS
        and has a  certificate  whose CA is in my JDK trust store.
        The service returns a gziped json response and accepts only for browser user agents.
        also this will log the kerberos handshake
    */
        DefaultHttpClient httpclient = new DefaultHttpClient();

        AuthUtils.securityLogging(SecurityLogType.KERBEROS,true)

        SSLUtils.trustJDKDefaultSSLCertificates();
        AuthUtils.useBrowserUserAgent();
        CredentialsUtils.setKerberosCredentials(client, new UsernamePasswordCredentials("xxx", "xxx"), "domain", "kdc");

        client.executeMethod(httpget);
        String responseString=AuthUtils.getResponseAsStringAndHandleGzip(httpget);

```

## TODO's
support httpclient 4

open for suggestions

## Developer
Dov Amir

dov.amir@jivesoftware.com

## License

    Copyright 2012 MASConsult Ltd.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.


