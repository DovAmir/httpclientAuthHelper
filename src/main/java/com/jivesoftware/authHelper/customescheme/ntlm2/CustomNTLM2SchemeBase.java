

package com.jivesoftware.authHelper.customescheme.ntlm2;


import java.nio.charset.Charset;
import java.util.Locale;
import org.apache.commons.httpclient.auth.AuthScheme;
import org.apache.commons.httpclient.auth.MalformedChallengeException;



/**
 * Abstract authentication scheme class that serves as a basis
 * for all authentication schemes supported by HttpClient. This class
 * defines the generic way of parsing an authentication challenge. It
 * does not make any assumptions regarding the format of the challenge
 * nor does it impose any specific way of responding to that challenge.
 *
 *
 */
public abstract class CustomNTLM2SchemeBase implements AuthScheme {
    /**
     * The www authenticate challange header.
     */
    public static final String WWW_AUTH = "WWW-Authenticate";

    /**
     * The www authenticate response header.
     */
    public static final String WWW_AUTH_RESP = "Authorization";

    /**
     * The proxy authenticate challange header.
     */
    public static final String PROXY_AUTH = "Proxy-Authenticate";

    /**
     * The proxy authenticate response header.
     */
    public static final String PROXY_AUTH_RESP = "Proxy-Authorization";


    public enum ChallengeState {

        TARGET, PROXY

    }

    /** HTTP header definitions */
    public static final String TRANSFER_ENCODING = "Transfer-Encoding";
    public static final String CONTENT_LEN = "Content-Length";
    public static final String CONTENT_TYPE = "Content-Type";
    public static final String CONTENT_ENCODING = "Content-Encoding";
    public static final String EXPECT_DIRECTIVE = "Expect";
    public static final String CONN_DIRECTIVE = "Connection";
    public static final String TARGET_HOST = "Host";
    public static final String USER_AGENT = "User-Agent";
    public static final String DATE_HEADER = "Date";
    public static final String SERVER_HEADER = "Server";

    /** HTTP expectations */
    public static final String EXPECT_CONTINUE = "100-continue";

    /** HTTP connection control */
    public static final String CONN_CLOSE = "Close";
    public static final String CONN_KEEP_ALIVE = "Keep-Alive";

    /** Transfer encoding definitions */
    public static final String CHUNK_CODING = "chunked";
    public static final String IDENTITY_CODING = "identity";

    public static final Charset DEF_CONTENT_CHARSET = EncodingUtils.ISO_8859_1;
    public static final Charset DEF_PROTOCOL_CHARSET = EncodingUtils.ASCII;

    /**
     * @deprecated (4.2)
     */
    @Deprecated
    public static final String UTF_8 = "UTF-8";
    /**
     * @deprecated (4.2)
     */
    @Deprecated
    public static final String UTF_16 = "UTF-16";
    /**
     * @deprecated (4.2)
     */
    @Deprecated
    public static final String US_ASCII = "US-ASCII";
    /**
     * @deprecated (4.2)
     */
    @Deprecated
    public static final String ASCII = "ASCII";
    /**
     * @deprecated (4.2)
     */
    @Deprecated
    public static final String ISO_8859_1 = "ISO-8859-1";
    /**
     * @deprecated (4.2)
     */
    @Deprecated
    public static final String DEFAULT_CONTENT_CHARSET = ISO_8859_1;
    /**
     * @deprecated (4.2)
     */
    @Deprecated
    public static final String DEFAULT_PROTOCOL_CHARSET = US_ASCII;
    /**
     * @deprecated (4.2)
     */
    @Deprecated
    public final static String OCTET_STREAM_TYPE = "application/octet-stream";
    /**
     * @deprecated (4.2)
     */
    @Deprecated
    public final static String PLAIN_TEXT_TYPE = "text/plain";
    /**
     * @deprecated (4.2)
     */
    @Deprecated
    public final static String CHARSET_PARAM = "; charset=";
    /**
     * @deprecated (4.2)
     */
    @Deprecated
    public final static String DEFAULT_CONTENT_TYPE = OCTET_STREAM_TYPE;


    private ChallengeState challengeState;

    /**
     * Creates an instance of <tt>AuthSchemeBase</tt> with the given challenge
     * state.
     *
     * @since 4.2
     */
    public CustomNTLM2SchemeBase(final ChallengeState challengeState) {
        super();
        this.challengeState = challengeState;
    }

    public CustomNTLM2SchemeBase() {
        this(null);
    }

    /**
     * Processes the given challenge token. Some authentication schemes
     * may involve multiple challenge-response exchanges. Such schemes must be able
     * to maintain the state information when dealing with sequential challenges
     *
     * @param authheader the challenge header
     *
     * @throws MalformedChallengeException is thrown if the authentication challenge
     * is malformed
     */
    public void processChallenge(final String authheader) throws MalformedChallengeException {
        if (authheader == null) {
            throw new IllegalArgumentException("Header may not be null");
        }
        //String authheader = header.getName();
        /* TEST
        if (authheader.equalsIgnoreCase(WWW_AUTH)) {
            this.challengeState = ChallengeState.TARGET;
        } else if (authheader.equalsIgnoreCase(PROXY_AUTH)) {
            this.challengeState = ChallengeState.PROXY;
        } else {
            throw new MalformedChallengeException("Unexpected header name: " + authheader);
        }     */

        CharArrayBuffer buffer;
        int pos;
       /* if (header instanceof FormattedHeader) {
            buffer = ((FormattedHeader) header).getBuffer();
            pos = ((FormattedHeader) header).getValuePos();
        } else {
            String s = header.getValue();  */
        String s = authheader;
        if (s == null) {
            throw new MalformedChallengeException("Header value is null");
        }
        buffer = new CharArrayBuffer(s.length());
        buffer.append(s);
        pos = 0;
        //}
        while (pos < buffer.length() && EncodingUtils.isWhitespace(buffer.charAt(pos))) {
            pos++;
        }
        int beginIndex = pos;
        while (pos < buffer.length() && !EncodingUtils.isWhitespace(buffer.charAt(pos))) {
            pos++;
        }
        int endIndex = pos;
        String s2 = buffer.substring(beginIndex, endIndex);
        if (!s2.equalsIgnoreCase(getSchemeName())) {
            throw new MalformedChallengeException("Invalid scheme identifier: " + s2);
        }

        parseChallenge(buffer, pos, buffer.length());
    }


    public String authenticate(org.apache.commons.httpclient.Credentials credentials, String method,
                               String uri) throws org.apache.commons.httpclient.auth.AuthenticationException {
        throw new RuntimeException(
                "Not implemented as it is deprecated anyway in Httpclient 3.x");
    }

    public String getID() {
        throw new RuntimeException(
                "Not implemented as it is deprecated anyway in Httpclient 3.x");
    }

    protected abstract void parseChallenge(
            CharArrayBuffer buffer, int beginIndex, int endIndex) throws MalformedChallengeException;

    /**
     * Returns <code>true</code> if authenticating against a proxy, <code>false</code>
     * otherwise.
     */
    public boolean isProxy() {
        return this.challengeState != null && this.challengeState == ChallengeState.PROXY;
    }

    /**
     * Returns {@link ChallengeState} value or <code>null</code> if unchallenged.
     *
     * @since 4.2
     */
    public ChallengeState getChallengeState() {
        return this.challengeState;
    }

    @Override
    public String toString() {
        String name = getSchemeName();
        if (name != null) {
            return name.toUpperCase(Locale.US);
        } else {
            return super.toString();
        }
    }

    public String getSchemeName() {
        return "ntlm";
    }

}
