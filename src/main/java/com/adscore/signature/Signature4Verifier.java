
package com.adscore.signature;

/**
 * Entry point of AdScore signature v4 verification library. It expose verify method allowing to verify
 * AdScore signature against given set of ipAddress(es) for given zone.
 */
public class Signature4Verifier {

  public static final int DEFAULT_EXPIRY_TIME_SEC = 60;

  /**
   * Default request and signature expiration is set to 60s
   *
   * @param signature the string which we want to verify
   * @param userAgent string with full description of user agent like 'Mozilla/5.0 (Linux; Android
   *     9; SM-J530F)...'
   * @param signRole string which specifies if we operate in customer or master role. For AdScore
   *     customers this should be always set to 'customer'
   * @param key string containing related zone key
   * @param ipAddresses array of strings containing ip4 or ip6 addresses against which we check
   *     signature. Usually, is fulfilled from httpXForwardForIpAddresses or/and remoteIpAddresses
   *     header. All possible ip addresses may be provided at once, in case of correct result,
   *     verifier returns list of chosen ip addresses that matched with the signature.
   * @return VerificationResult
   * @throws VersionError If there is an error related to version parsing or compatibility.
   * @throws ParseError If there is an error parsing the signature or during decryption process
   * @throws VerifyError If there is an error during verify decrypted Signature
   */
  public static Signature4VerificationResult verify(
      String signature, String userAgent, String signRole, String key, String... ipAddresses) throws VersionError, VerifyError, ParseError {
    return Signature4Verifier.verify(
        signature, userAgent, signRole, key, true, DEFAULT_EXPIRY_TIME_SEC, ipAddresses);
  }

  /**
   * @param signature the string which we want to verify
   * @param userAgent string with full description of user agent like 'Mozilla/5.0 (Linux; Android
   *     9; SM-J530F)...'
   * @param signRole string which specifies if we operate in customer or master role. For AdScore
   *     customers this should be always set to 'customer'
   * @param key string containing related zone key
   * @param ipAddresses array of strings containing ip4 or ip6 addresses against which we check
   *     signature. Usually, is fulfilled from httpXForwardForIpAddresses or/and remoteIpAddresses
   *     header. All possible ip addresses may be provided at once, in case of correct result,
   *     verifier returns list of chosen ip addresses that matched with the signature.
   * @param expiry number which is time in seconds. IF signatureTime + expiry > CurrentDateInSeconds
   *     THEN result is expired
   * @return VerificationResult
   * @throws VersionError If there is an error related to version parsing or compatibility.
   * @throws ParseError If there is an error parsing the signature or during decryption process
   * @throws VerifyError If there is an error during verify decrypted Signature
   */
  public static Signature4VerificationResult verify(
      String signature,
      String userAgent,
      String signRole,
      String key,
      Integer expiry,
      String... ipAddresses) throws VersionError, VerifyError, ParseError {

    return Signature4Verifier.verify(signature, userAgent, signRole, key, true, expiry, ipAddresses);
  }

  /**
   * Default request and signature expiration is set to 60s
   *
   * @param signature the string which we want to verify
   * @param userAgent string with full description of user agent like 'Mozilla/5.0 (Linux; Android
   *     9; SM-J530F)...'
   * @param signRole string which specifies if we operate in customer or master role. For AdScore
   *     customers this should be always set to 'customer'
   * @param key string containing related zone key
   * @param ipAddresses array of strings containing ip4 or ip6 addresses against which we check
   *     signature. Usually, is fulfilled from httpXForwardForIpAddresses or/and remoteIpAddresses
   *     header. All possible ip addresses may be provided at once, in case of correct result,
   *     verifier returns list of chosen ip addresses that matched with the signature.
   * @param isKeyBase64Encoded boolean defining if passed key is base64 encoded or not
   * @return VerificationResult
   * @throws VersionError If there is an error related to version parsing or compatibility.
   * @throws ParseError If there is an error parsing the signature or during decryption process
   * @throws VerifyError If there is an error during verify decrypted Signature
   */
  public static Signature4VerificationResult verify(
      String signature,
      String userAgent,
      String signRole,
      String key,
      boolean isKeyBase64Encoded,
      String... ipAddresses) throws VersionError, VerifyError, ParseError {

    return Signature4Verifier.verify(
        signature,
        userAgent,
        signRole,
        key,
        isKeyBase64Encoded,
        DEFAULT_EXPIRY_TIME_SEC,
        ipAddresses);
  }

  /**
   * @param signature the string which we want to verify
   * @param userAgent string with full description of user agent like 'Mozilla/5.0 (Linux; Android
   *     9; SM-J530F)...'
   * @param signRole string which specifies if we operate in customer or master role. For AdScore
   *     customers this should be always set to 'customer'
   * @param key string containing related zone key
   * @param ipAddresses array of strings containing ip4 or ip6 addresses against which we check
   *     signature. Usually, is fulfilled from httpXForwardForIpAddresses or/and remoteIpAddresses
   *     header. All possible ip addresses may be provided at once, in case of correct result,
   *     verifier returns list of chosen ip addresses that matched with the signature.
   * @param expiry number which is time in seconds. IF signatureTime + expiry > CurrentDateInSeconds
   *     THEN result is expired
   * @param isKeyBase64Encoded boolean defining if passed key is base64 encoded or not
   * @return VerificationResult
   * @throws VersionError If there is an error related to version parsing or compatibility.
   * @throws ParseError If there is an error parsing the signature or during decryption process
   * @throws VerifyError If there is an error during verify decrypted Signature
   */
  public static Signature4VerificationResult verify(
      String signature,
      String userAgent,
      String signRole,
      String key,
      boolean isKeyBase64Encoded,
      Integer expiry,
      String... ipAddresses) throws VersionError, VerifyError, ParseError {

    return new Signature4VerifierService()
        .verifySignature(
            signature, userAgent, signRole, key, isKeyBase64Encoded, expiry, ipAddresses);
  }
}
