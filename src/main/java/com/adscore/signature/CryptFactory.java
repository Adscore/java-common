package com.adscore.signature;

import java.nio.ByteBuffer;
import java.util.Arrays;

import static com.adscore.signature.SignatureVerifierUtils.substrBuffer;


class CryptFactory {

    static AbstractSymmetricCrypt createFromPayload(ByteBuffer payload) throws SignatureParseError {
        byte[] header = substrBuffer(payload, 0, 2).array();
        return createCrypt(header);
    }

    private static AbstractSymmetricCrypt createCrypt(byte[] name) throws SignatureParseError {
        if (Arrays.equals(name,PhpUnpack.pack("v", OpenSSL.METHOD))){
            return new OpenSSL();
        }

        if (Arrays.equals(name,PhpUnpack.pack("v", OpenSSLAEAD.METHOD))){
            return new OpenSSLAEAD();
        }

        if (Arrays.equals(name,PhpUnpack.pack("v", Secretbox.METHOD))){
            return new Secretbox();
        }
        throw new SignatureParseError("Unsupported crypt class");
    }
}
