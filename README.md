# Httpclient Authentication Helper

## What is it?
A library that helps authenticate Httpclient 3  with services that use  NTLM, KERBEROS, SSL authentications.

The design goals are to be unobstrusive and simple to use.
The library uses default configurations that apply to 99% of the use cases, so that the developer wont
have to concern himself with the details of his chosen authentication mechansim.

The main features are:

* support NTLM v1 and NTLMv2
* support KERBEROS without the need for external files (login.conf,krb.ini )
* support SSL in 3 modes- trust all certificates, trust JDK truststore (cacerts), trust custom truststore
* vairious tools - logging for security, cryptography providers, use browser user agent, handle gzipped response, etc...

## How to use?

Example:
```
    /*
        example 1: connect to a service on a windows iis server that is protected by NTLMv2
        and has a self signed certificate
    */
    DefaultHttpClient httpclient = new DefaultHttpClient();

    AuthUtils.trustAllSSLCertificates();
    AuthUtils.setNTLMCredentials(client, new UsernamePasswordCredentials("xxx", "xxx"), "mydomain");

    client.executeMethod(httpget);

    /*
        example 2: connect to a service  that is protected by KERBEROS
        and has a  certificate  whose CA is in my JDK trust store.
        The service returns a gziped json response and accepts only for browser user agents.
        also this will log the kerberos handshake
    */
        DefaultHttpClient httpclient = new DefaultHttpClient();

        AuthUtils.securityLogging(SecurityLogType.KERBEROS,true)

        AuthUtils.trustJDKDefaultSSLCertificates();
        AuthUtils.useBrowserUserAgent();
        AuthUtils.setKerberosCredentials(client, new UsernamePasswordCredentials("xxx", "xxx"), "domain", "kdc");

        client.executeMethod(httpget);
        String responseString=AuthUtils.getResponseAsStringAndHandleGzip(httpget);

```

## TODO's
support httpclient 4 (for all featurs except NTLM support that is already built in httpclient4)
support OAUTH
support cryptography helpers to create keys and encrypt\decrypt

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


