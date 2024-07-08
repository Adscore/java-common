package com.adscore.signature.v5.utils;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Base64Util {
    /**
     * Encodes a string into Base64 format.
     * @param input The input string to encode.
     * @return The Base64 encoded string.
     */
    public static String base64Encode(String input) {
        return Base64.getEncoder().encodeToString(input.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Decodes a Base64 encoded string into a byte array.
     * @param base64Input The Base64 encoded string to decode.
     * @return The decoded byte array.
     */
    public static byte[] base64Decode(String base64Input) {
        if (base64Input.contains("-")){
            return Base64.getUrlDecoder().decode(base64Input);
        }
        return Base64.getDecoder().decode(base64Input);
    }

    /**
     * Binary to ASCII conversion
     * @param value
     * @param format
     * @return String
     */
    public static String base64DecodeByFormat(String value, Base64Format format) {
        byte[] bytes = value.getBytes();
        switch (format) {
            case BASE64_VARIANT_ORIGINAL:
                return Base64.getEncoder().encodeToString(bytes);
            case BASE64_VARIANT_ORIGINAL_NO_PADDING:
                return Base64.getEncoder().withoutPadding().encodeToString(bytes);
            case BASE64_VARIANT_URLSAFE:
                return Base64.getUrlEncoder().encodeToString(bytes);
            case BASE64_VARIANT_URLSAFE_NO_PADDING:
                return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
            default:
                throw new IllegalArgumentException("Invalid base64 format");
        }
    }
}
