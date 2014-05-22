package com.jivesoftware.authHelper.consts;

/**
 * Created with IntelliJ IDEA.
 * User: dovamir
 * Date: 5/15/14
 * Time: 9:50 PM
 * To change this template use File | Settings | File Templates.
 */
public enum SecurityLogType {
    ALL("javax.net.debug"), KERBEROS("sun.security.krb5.debug"), SSL("javax.net.debug");

    private String logtype;

    private SecurityLogType(String logtype) {
        this.logtype = logtype;
    }

    public String getLogtype() {
        return logtype;
    }


}
