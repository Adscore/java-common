package com.adscore.signature;

import java.util.List;
/**
 * Entry point of AdScore signature v5 verification library. It expose verify method allowing to verify
 * AdScore signature against given set of ipAddress(es) for given zone.
 *
 * V5 is in fact an encrypted payload containing various metadata about the traffic.
 * Its decryption does not rely on IP address nor User Agent string,
 * so it is immune for environment changes usually preventing V4 to be even decoded.
 * result is also included in the payload, but client doing the integration can make its own decision basing on the metadata accompanying.
 *
 */
public class Signature5Verifier {

    /**
     * Verifies the signature against the provided user agent, key, and IP addresses.
     *
     * @param signature The string which we want to verify.
     * @param userAgent String with full description of user agent like 'Mozilla/5.0 (Linux; Android 9; SM-J530F)...'.
     * @param key "Zone Response Key" which you might find in "Zone Encryption" page.
     * @param ipAddresses List of strings containing IPv4 or IPv6 addresses against which we check signature.
     *                    Usually fulfilled from httpXForwardForIpAddresses or/and remoteIpAddresses header.
     *                    All possible IP addresses may be provided at once; the verifier returns a list of chosen
     *                    IP addresses that matched with the signature.
     * @return Signature5VerificationResult object representing the result of the signature verification.
     * @throws VersionError If there is an error related to version parsing or compatibility.
     * @throws ParseError If there is an error parsing the signature or during decryption process
     * @throws VerifyError If there is an error during verify decrypted Signature
     */
    public static Signature5VerificationResult verify(
            String signature,
            String userAgent,
            String key,
            List<String> ipAddresses) throws VersionError, ParseError, VerifyError {
        return new Signature5VerifierService().createFromRequest(signature, userAgent, key, ipAddresses);
    }
}
