package com.adscore.signature;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * General-purpose utilities, that help with string manipulations, encoding/decoding adscore key
 * etc.
 */
class SignatureVerifierUtils {

  static int characterToInt(Object obj) {
    if (obj instanceof Short){
      return (int) (short) obj;
    }
    return (int) obj;
  }

   static String encode(String key, String data) throws SignatureParseError {
    try {
      String algorithm = "HmacSHA256";
      Mac mac = Mac.getInstance(algorithm);
      mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.ISO_8859_1), algorithm));

      byte[] digest = mac.doFinal(data.getBytes());
      return new String(digest, StandardCharsets.ISO_8859_1);
    } catch (Exception e){
      throw new SignatureParseError("Error encode data");
    }
  }

  /**
   * @param key in base64 format
   * @return decoded key
   */
  static String keyDecode(String key) {
    return atob(key);
  }

  static String atob(String str) {
    return new String(Base64.getMimeDecoder().decode(str.getBytes()), StandardCharsets.ISO_8859_1);
  }

  static String padStart(String inputString, int length, char c) {
    if (inputString.length() >= length) {
      return inputString;
    }
    StringBuilder sb = new StringBuilder();
    while (sb.length() < length - inputString.length()) {
      sb.append(c);
    }
    sb.append(inputString);

    return sb.toString();
  }

  /**
   * Encodes a string into Base64 format.
   * @param input The input string to encode.
   * @return The Base64 encoded string.
   */
  static String base64Encode(String input) {
    return Base64.getEncoder().encodeToString(input.getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Decodes a Base64 encoded string into a byte array.
   * @param base64Input The Base64 encoded string to decode.
   * @return The decoded byte array.
   */
  static byte[] base64Decode(String base64Input) {
    if (base64Input.contains("-") || base64Input.contains("_")){
      return Base64.getUrlDecoder().decode(base64Input.getBytes(StandardCharsets.UTF_8));
    }
    return Base64.getDecoder().decode(base64Input);
  }

  static byte[] toByteArray(ByteBuffer buffer) {
    byte[] bytes = new byte[buffer.remaining()];
    buffer.get(bytes);
    return bytes;
  }

  static int strpos(String input, String searchFor, int offset) {
    if (input == null || searchFor == null) {
      return -1;
    }
    return input.indexOf(searchFor, offset);
  }

  static String substr(String input, int offset, Integer length) {
    if (length != null) {
      return input.substring(offset, offset + length);
    }
    return input.substring(offset);
  }

  static ByteBuffer substrBuffer(ByteBuffer input, int offset, Integer length) {
    if (length != null) {
      byte[] bytes = Arrays.copyOfRange(input.array(), offset, offset + length);
      return ByteBuffer.wrap(bytes);
    }
    return ByteBuffer.wrap(Arrays.copyOfRange(input.array(), offset, input.capacity()));
  }
}
