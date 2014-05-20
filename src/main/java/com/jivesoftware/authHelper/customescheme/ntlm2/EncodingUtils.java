package com.jivesoftware.authHelper.customescheme.ntlm2;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;


/**
 * The home for utility methods that handle various encoding tasks.
 *
 */
public final class EncodingUtils {

    public static final int CR = 13; // <US-ASCII CR, carriage return (13)>
    public static final int LF = 10; // <US-ASCII LF, linefeed (10)>
    public static final int SP = 32; // <US-ASCII SP, space (32)>
    public static final int HT = 9;  // <US-ASCII HT, horizontal-tab (9)>

    public static final Charset UTF_8 = Charset.forName("UTF-8");
    public static final Charset ASCII = Charset.forName("US-ASCII");
    public static final Charset ISO_8859_1 = Charset.forName("ISO-8859-1");


    public static boolean isWhitespace(char ch) {
        return ch == EncodingUtils.SP || ch == EncodingUtils.HT || ch == EncodingUtils.CR || ch == EncodingUtils.LF;
    }

    /**
     * Converts the byte array of HTTP content characters to a string. If
     * the specified charset is not supported, default system encoding
     * is used.
     *
     * @param data the byte array to be encoded
     * @param offset the index of the first byte to encode
     * @param length the number of bytes to encode
     * @param charset the desired character encoding
     * @return The result of the conversion.
     */
    public static String getString(
        final byte[] data,
        int offset,
        int length,
        String charset
    ) {

        if (data == null) {
            throw new IllegalArgumentException("Parameter may not be null");
        }

        if (charset == null || charset.length() == 0) {
            throw new IllegalArgumentException("charset may not be null or empty");
        }

        try {
            return new String(data, offset, length, charset);
        } catch (UnsupportedEncodingException e) {
            return new String(data, offset, length);
        }
    }


    /**
     * Converts the byte array of HTTP content characters to a string. If
     * the specified charset is not supported, default system encoding
     * is used.
     *
     * @param data the byte array to be encoded
     * @param charset the desired character encoding
     * @return The result of the conversion.
     */
    public static String getString(final byte[] data, final String charset) {
        if (data == null) {
            throw new IllegalArgumentException("Parameter may not be null");
        }
        return getString(data, 0, data.length, charset);
    }

    /**
     * Converts the specified string to a byte array.  If the charset is not supported the
     * default system charset is used.
     *
     * @param data the string to be encoded
     * @param charset the desired character encoding
     * @return The resulting byte array.
     */
    public static byte[] getBytes(final String data, final String charset) {

        if (data == null) {
            throw new IllegalArgumentException("data may not be null");
        }

        if (charset == null || charset.length() == 0) {
            throw new IllegalArgumentException("charset may not be null or empty");
        }

        try {
            return data.getBytes(charset);
        } catch (UnsupportedEncodingException e) {
            return data.getBytes();
        }
    }

    /**
     * Converts the specified string to byte array of ASCII characters.
     *
     * @param data the string to be encoded
     * @return The string as a byte array.
     */
    public static byte[] getAsciiBytes(final String data) {

        if (data == null) {
            throw new IllegalArgumentException("Parameter may not be null");
        }

        try {
            return data.getBytes(ASCII.name());
        } catch (UnsupportedEncodingException e) {
            throw new Error("HttpClient requires ASCII support");
        }
    }

    /**
     * Converts the byte array of ASCII characters to a string. This method is
     * to be used when decoding content of HTTP elements (such as response
     * headers)
     *
     * @param data the byte array to be encoded
     * @param offset the index of the first byte to encode
     * @param length the number of bytes to encode
     * @return The string representation of the byte array
     */
    public static String getAsciiString(final byte[] data, int offset, int length) {

        if (data == null) {
            throw new IllegalArgumentException("Parameter may not be null");
        }

        try {
            return new String(data, offset, length, ASCII.name());
        } catch (UnsupportedEncodingException e) {
            throw new Error("HttpClient requires ASCII support");
        }
    }

    /**
     * Converts the byte array of ASCII characters to a string. This method is
     * to be used when decoding content of HTTP elements (such as response
     * headers)
     *
     * @param data the byte array to be encoded
     * @return The string representation of the byte array
     */
    public static String getAsciiString(final byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Parameter may not be null");
        }
        return getAsciiString(data, 0, data.length);
    }

    /**
     * This class should not be instantiated.
     */
    private EncodingUtils() {
    }

}
