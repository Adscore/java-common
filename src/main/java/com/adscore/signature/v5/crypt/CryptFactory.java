package com.adscore.signature.v5.crypt;

import com.adscore.signature.v5.errors.SignatureParseError;
import com.adscore.signature.v5.utils.phputils.PhpUnpack;

import java.nio.ByteBuffer;
import java.util.Arrays;

import static com.adscore.signature.v5.utils.Utils.substrBuffer;

public class CryptFactory {
    public static AbstractSymmetricCrypt createFromPayload(ByteBuffer payload) throws SignatureParseError {
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
