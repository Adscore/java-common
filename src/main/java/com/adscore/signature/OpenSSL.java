package com.adscore.signature;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;

class OpenSSL extends AbstractSymmetricCrypt {
    static final int METHOD = 0x0200;

    private CryptMethod cryptMethod = CryptMethod.AES_256_CBC;

    OpenSSL() {}

     byte[] decryptWithKey(ByteBuffer payload, byte[] key) throws DecryptError {
        HashMap<String, Integer> lengths = new HashMap(){{put("iv", cryptMethod.getIvLength());}};
        DecryptResult result = this.parse(payload, lengths);

        if (result.getMethod() != OpenSSL.METHOD) {
            throw new DecryptError("Unrecognized payload");
        }

        return this.decode(result.getData().array(), "AES/CBC/PKCS5Padding", key, result.getByteBufferMap().get("iv").array());
    }

    private byte[] decode(byte[] input, String method, byte[] key, byte[] iv) throws DecryptError {
        try {
            Cipher cipher = Cipher.getInstance(method);
            ByteBuffer buffer = ByteBuffer.allocate(input.length);

            AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
            buffer.put(input);

            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, paramSpec);

            return cipher.doFinal(buffer.array());
        } catch (Exception e) {
            throw new DecryptError("Decryption OpenSSL failed " + e);
        }
    }
}
