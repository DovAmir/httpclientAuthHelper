package com.jivesoftware.extendedAuth.customescheme.negotiate;

import org.apache.commons.httpclient.NTCredentials;

/**
 * Created with IntelliJ IDEA.
 * User: dovamir
 * Date: 4/29/14
 * Time: 7:40 PM
 * To change this template use File | Settings | File Templates.
 */
public class KerberosCredentials extends NTCredentials {

    String kdc;


    public void setKdc(String kdc) {
        this.kdc = kdc;
    }


    public String getKdc() {
        return kdc;
    }
}
