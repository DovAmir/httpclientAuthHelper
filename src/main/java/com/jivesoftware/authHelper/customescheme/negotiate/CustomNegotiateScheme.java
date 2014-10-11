/*
 * $Header:$
 * $Revision$
 * $Date$
 *
 * ====================================================================
 *
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */

package com.jivesoftware.authHelper.customescheme.negotiate;

import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.commons.codec.binary.Base64;

import org.apache.commons.httpclient.Credentials;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.commons.httpclient.auth.*;
import org.ietf.jgss.*;


/**
 * Created with IntelliJ IDEA.
 * User: dov2
 * Date: 7/3/12
 * Time: 3:22 PM
 * To change this template use File | Settings | File Templates.
 */
public class CustomNegotiateScheme implements AuthScheme {
    /** Log object for this class. */
    private static final Logger LOG = Logger.getLogger(CustomNegotiateScheme.class.getName());

    /** challenge string. */
    private String challenge = null;

    private static final int UNINITIATED = 0;
    private static final int INITIATED = 1;
    private static final int NEGOTIATING = 3;
    private static final int ESTABLISHED = 4;
    private static final int FAILED = Integer.MAX_VALUE;

    private static final int MAX_RETRY_COUNT = 10;

    private GSSContext context = null;

    /** Authentication process state */
    private int state;

    /** base64 decoded challenge **/
    byte[] token = new byte[0];

    private int retryCount = 0;


        /*
    this function represents the config file described in
    http://hc.apache.org/httpcomponents-client-ga/tutorial/html/authentication.html#d5e790
    and can be modified if needed
     */
     private CustomConfiguration getCustomConfiguration(UsernamePasswordCredentials credentials) {
        AppConfigurationEntry[] defaultConfiguration = new AppConfigurationEntry[1];
        Map options = new HashMap();
        options.put("principal", credentials.getUserName());
        options.put("client", "true");
        options.put("debug", "false");
        defaultConfiguration[0] = new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",
                AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
        return new CustomConfiguration(defaultConfiguration);
    }


    /**
     * Init GSSContext for negotiation.
     *
     * @param server servername only (e.g: radar.it.su.se)
     */
    protected void init(String server, UsernamePasswordCredentials credentials) throws GSSException {
        LOG.info("init " + server);

        // Create a callback handler
        Configuration.setConfiguration(null);
        CallbackHandler callbackHandler = new CustomNegotiateCallbackHandler(credentials.getUserName(),
                credentials.getPassword());
        PrivilegedExceptionAction action = new MyAction(server);
        LoginContext con = null;

        try {
            CustomConfiguration cc = getCustomConfiguration(credentials);

            // Create a LoginContext with a callback handler
            con = new LoginContext("com.sun.security.jgss.login", null, callbackHandler, cc);

            Configuration.setConfiguration(cc);
            // Perform authentication
            con.login();
        } catch (LoginException e) {
            System.err.println("Login failed");
            e.printStackTrace();
            // System.exit(-1);
            throw new RuntimeException(e);
        } catch (Exception e) {
            System.err.println("Login failed");
            e.printStackTrace();
            // System.exit(-1);
            throw new RuntimeException(e);
        }

        // Perform action as authenticated user
        Subject subject = con.getSubject();
        //LOG.trace("Subject is :"+ subject.toString());

        LOG.info("Authenticated principal:**** " +
                subject.getPrincipals());

        try {
            Subject.doAs(subject, action);
        } catch (PrivilegedActionException e) {
            e.printStackTrace();

        } catch (Exception e) {
            e.printStackTrace();

        }


    }

    /**
     * Default constructor for the Negotiate authentication scheme.
     *
     * @since 3.0
     */
    public CustomNegotiateScheme() {
        super();
        state = UNINITIATED;
    }

    /**
     * Constructor for the Negotiate authentication scheme.
     *
     * @param challenge The authentication challenge
     */
    public CustomNegotiateScheme(final String challenge) {
        super();
        LOG.info("enter CustomNegotiateScheme(" + challenge + ")");
        processChallenge(challenge);
    }

    /**
     * Processes the Negotiate challenge.
     *
     * @param challenge the challenge string
     *
     * @since 3.0
     */
    public void processChallenge(final String challenge) {
        //System.out.println("%%%%in process challenge%%% challenge="+challenge);
        LOG.info("enter processChallenge(challenge=\"" + challenge + "\")");
        if (challenge.startsWith("Negotiate")) {
            if (!isComplete()) {
                if (retryCount++ > MAX_RETRY_COUNT) {
                    state = FAILED;
                    LOG.info("*** Failed to negotiate authentication after " + MAX_RETRY_COUNT +
                            " retries. Giving up. ***");
                } else {
                    state = NEGOTIATING;
                }
            }

            if (challenge.startsWith("Negotiate ")) {
                token = new Base64().decode(challenge.substring(10).getBytes());
            }

        } else {
            token = new byte[0];
        }
    }

    /**
     * Tests if the Negotiate authentication process has been completed.
     *
     * @return <tt>true</tt> if authorization has been processed,
     *   <tt>false</tt> otherwise.
     *
     * @since 3.0
     */
    public boolean isComplete() {
        LOG.info("enter isComplete()");
        return this.state == ESTABLISHED || this.state == FAILED;
    }

    /**
     * Returns textual designation of the Negotiate authentication scheme.
     *
     * @return <code>Negotiate</code>
     */
    public String getSchemeName() {
        return "Negotiate";
    }

    /**
     * The concept of an authentication realm is not supported by the Negotiate
     * authentication scheme. Always returns <code>null</code>.
     *
     * @return <code>null</code>
     */
    public String getRealm() {
        return null;
    }

    /**
     * Returns a String identifying the authentication challenge.  This is
     * used, in combination with the host and port to determine if
     * authorization has already been attempted or not.  Schemes which
     * require multiple requests to complete the authentication should
     * return a different value for each stage in the request.
     *
     * <p>Additionally, the ID should take into account any changes to the
     * authentication challenge and return a different value when appropriate.
     * For example when the realm changes in basic authentication it should be
     * considered a different authentication attempt and a different value should
     * be returned.</p>
     *
     * @return String a String identifying the authentication challenge.  The
     * returned value may be null.
     *
     * @deprecated no longer used
     */
    @Deprecated
    public String getID() {
        LOG.info("enter getID(): " + challenge);
        return challenge;
    }

    /**
     * Returns the authentication parameter with the given name, if available.
     *
     * <p>There are no valid parameters for Negotiate authentication so this
     * method always returns <tt>null</tt>.</p>
     *
     * @param name The name of the parameter to be returned
     *
     * @return the parameter with the given name
     */
    public String getParameter(String name) {
        LOG.info("enter getParameter(" + name + ")");
        if (name == null) {
            throw new IllegalArgumentException("Parameter name may not be null");
        }
        return null;
    }

    /**
     * Returns <tt>true</tt>.
     * Negotiate authentication scheme is connection based.
     *
     * @return <tt>true</tt>.
     *
     * @since 3.0
     */
    public boolean isConnectionBased() {
        LOG.info("enter isConnectionBased()");
        return true;
    }

    /**
     * Method not supported by Negotiate scheme.
     *
     * @throws org.apache.commons.httpclient.auth.AuthenticationException if called.
     *
     * @deprecated Use {@link #authenticate(org.apache.commons.httpclient.Credentials, org.apache.commons.httpclient.HttpMethod)}
     */
    @Deprecated
    public String authenticate(Credentials credentials, String method, String uri)
            throws AuthenticationException {
        throw new AuthenticationException("method not supported by Negotiate scheme");
    }

    /**
     * Produces Negotiate authorization string based on token created by
     * processChallenge.
     *
     * @param credentials Never used be the Negotiate scheme but must be provided to
     * satisfy common-httpclient API. Credentials from JAAS will be used insted.
     * @param method The method being authenticated
     *
     * @throws org.apache.commons.httpclient.auth.AuthenticationException if authorization string cannot
     *   be generated due to an authentication failure
     *
     * @return an Negotiate authorization string
     *
     * @since 3.0
     */
    public synchronized String authenticate(
            Credentials credentials,
            HttpMethod method
    ) throws AuthenticationException {
        LOG.info("enter CustomNegotiateScheme.authenticate(Credentials, HttpMethod)");

        if (state == UNINITIATED) {
            throw new IllegalStateException(
                    "Negotiation authentication process has not been initiated");
        }

        try {
            try {
                if (context == null) {
                    LOG.info("host: " + method.getURI().getHost());
                    init(method.getURI().getHost(), (UsernamePasswordCredentials) credentials);
                }
            } catch (org.apache.commons.httpclient.URIException urie) {
                LOG.severe(urie.getMessage());
                state = FAILED;
                throw new AuthenticationException(urie.getMessage());
            }

            // HTTP 1.1 issue:
            // Mutual auth will never complete do to 200 insted of 401 in
            // return from server. "state" will never reach ESTABLISHED
            // but it works anyway

            //            token = context.initSecContext(token, 0, token.length);
            LOG.info("got token, sending " + token.length + " to server");
        } catch (GSSException gsse) {
            LOG.severe(gsse.getMessage());
            state = FAILED;
            if (gsse.getMajor() == GSSException.DEFECTIVE_CREDENTIAL
                    || gsse.getMajor() == GSSException.CREDENTIALS_EXPIRED) {
                throw new InvalidCredentialsException(gsse.getMessage(), gsse);
            }
            if (gsse.getMajor() == GSSException.NO_CRED) {
                throw new CredentialsNotAvailableException(gsse.getMessage(), gsse);
            }
            if (gsse.getMajor() == GSSException.DEFECTIVE_TOKEN
                    || gsse.getMajor() == GSSException.DUPLICATE_TOKEN
                    || gsse.getMajor() == GSSException.OLD_TOKEN) {
                throw new AuthChallengeException(gsse.getMessage(), gsse);
            }
            // other error
            throw new AuthenticationException(gsse.getMessage());
        }
        return "Negotiate " + new String(new Base64(-1).encode(token));
    }

    // Action to perform
    class MyAction implements PrivilegedExceptionAction {
        private String ser;

        MyAction(String server) {
            this.ser = server;
        }

        /**
         * Returns the Universal Object Identifier representation of
         * the SPNEGO mechanism.
         *
         * @return Object Identifier of the GSS-API mechanism
         */
        private Oid getOid() {
            Oid oid = null;
            try {
                oid = new Oid("1.3.6.1.5.5.2");
            } catch (GSSException gsse) {

            }
            return oid;
        }

        public Object run() throws Exception {
            // Replace the following with an action to be performed
            // by authenticated user

            Oid krb5Oid = getOid(); // new Oid("1.2.840.113554.1.2.2");

            GSSManager manager = GSSManager.getInstance();
            GSSName serverName = manager.createName("HTTP@" + this.ser, GSSName.NT_HOSTBASED_SERVICE, getOid());
            GSSContext context = manager.createContext(serverName,
                    krb5Oid,
                    null,
                    GSSContext.DEFAULT_LIFETIME);

            // Set the desired optional features on the context. The client
            // chooses these options.

            context.requestMutualAuth(true);  // Mutual authentication
            context.requestConf(true);  // Will use confidentiality later
            context.requestInteg(true); // Will use integrity later


            // token is ignored on the first call
            token = context.initSecContext(token, 0, token.length);

            return null;

        }
    }
}
