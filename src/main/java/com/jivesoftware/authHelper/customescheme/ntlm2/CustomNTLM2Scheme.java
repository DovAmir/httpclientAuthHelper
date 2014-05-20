
package com.jivesoftware.authHelper.customescheme.ntlm2;

import org.apache.commons.httpclient.Credentials;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.NTCredentials;
import org.apache.commons.httpclient.auth.AuthenticationException;
import org.apache.commons.httpclient.auth.InvalidCredentialsException;
import org.apache.commons.httpclient.auth.MalformedChallengeException;


/**
 * NTLM is a proprietary authentication scheme developed by Microsoft
 * and optimized for Windows platforms.
 *
 */
public class CustomNTLM2Scheme extends CustomNTLM2SchemeBase {

    enum State {
        UNINITIATED,
        CHALLENGE_RECEIVED,
        MSG_TYPE1_GENERATED,
        MSG_TYPE2_RECEVIED,
        MSG_TYPE3_GENERATED,
        FAILED,
    }

    private CustomNTLM2Engine engine;

    private State state;
    private String challenge;


    public CustomNTLM2Scheme() {
        super();
        if (engine == null) {
            engine = new CustomNTLM2Engine();
        }
        this.state = State.UNINITIATED;
        this.challenge = null;
    }

    public CustomNTLM2Scheme(final CustomNTLM2Engine engine) {
        super();
        if (engine == null) {
            throw new IllegalArgumentException("NTLM engine may not be null");
        }
        this.engine = engine;
        this.state = State.UNINITIATED;
        this.challenge = null;
    }

    public String getSchemeName() {
        return "ntlm";
    }

    public String getParameter(String name) {
        // String parameters not supported
        return null;
    }

    public String getRealm() {
        // NTLM does not support the concept of an authentication realm
        return null;
    }

    public boolean isConnectionBased() {
        return true;
    }


    protected void parseChallenge(
            final CharArrayBuffer buffer,
            int beginIndex, int endIndex) throws MalformedChallengeException {
        String challenge = buffer.substringTrimmed(beginIndex, endIndex);
        if (challenge.length() == 0) {
            if (this.state == State.UNINITIATED) {
                this.state = State.CHALLENGE_RECEIVED;
            } else {
                this.state = State.FAILED;
            }
            this.challenge = null;
        } else {
            this.state = State.MSG_TYPE2_RECEVIED;
            this.challenge = challenge;
        }
    }


    public String authenticate(
            final Credentials credentials,
            final HttpMethod method) throws AuthenticationException {
        NTCredentials ntcredentials = null;
        try {
            ntcredentials = (NTCredentials) credentials;
        } catch (ClassCastException e) {
            throw new InvalidCredentialsException(
                    "Credentials cannot be used for NTLM authentication: "
                            + credentials.getClass().getName());
        }
        String response = null;
        if (this.state == State.CHALLENGE_RECEIVED || this.state == State.FAILED) {
            response = this.engine.generateType1Msg(
                    ntcredentials.getDomain(),
                    ntcredentials.getHost());
            this.state = State.MSG_TYPE1_GENERATED;
        } else if (this.state == State.MSG_TYPE2_RECEVIED) {
            response = this.engine.generateType3Msg(
                    ntcredentials.getUserName(),
                    ntcredentials.getPassword(),
                    ntcredentials.getDomain(),
                    ntcredentials.getHost(),
                    this.challenge);
            this.state = State.MSG_TYPE3_GENERATED;
        } else {
            throw new AuthenticationException("Unexpected state: " + this.state);
        }
        CharArrayBuffer buffer = new CharArrayBuffer(32);

        buffer.append("NTLM ");
        buffer.append(response);
        return buffer.toString();
    }

    public boolean isComplete() {
        return this.state == State.MSG_TYPE3_GENERATED || this.state == State.FAILED;
    }


}
