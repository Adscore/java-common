package com.adscore.signature.v5;

import java.util.List;
/*
 * Copyright (c) 2024 AdScore Technologies DMCC [AE]
 *
 * Licensed under MIT License;
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
public class Signature5Verifier {

    /**
     * @param signature the string which we want to verify
     * @param userAgent string with full description of user agent like 'Mozilla/5.0 (Linux; Android
     *     9; SM-J530F)...'
     * @param key the string key
     * @param ipAddresses array of strings containing ip4 or ip6 addresses against which we check
     *     signature. Usually, is fulfilled from httpXForwardForIpAddresses or/and remoteIpAddresses
     *     header. All possible ip addresses may be provided at once, in case of correct result,
     *     verifier returns list of chosen ip addresses that matched with the signature.
     * @return VerificationResult
     */
    public static Signature5VerificationResult verify(
            String signature,
            String userAgent,
            String key,
            List<String> ipAddresses) {
        return new Signature5Service().createFromRequest(signature, userAgent, key, ipAddresses);
    }
}
