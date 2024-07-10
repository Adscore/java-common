package com.adscore.signature;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.spec.AlgorithmParameterSpec;
import java.util.LinkedHashMap;
import java.util.Map;

class OpenSSLAEAD extends AbstractSymmetricCrypt{
    public static final int METHOD = 0x0201;
    private CryptMethod cryptMethod = CryptMethod.AES_256_GCM;

    OpenSSLAEAD() {}

    byte[] decryptWithKey(ByteBuffer payload, byte[] key) throws DecryptError {
        Map<String,Integer> lengths = new LinkedHashMap(){{
            put("iv", cryptMethod.getIvLength());
            put("tag", 16);
        }};

        DecryptResult parse = this.parse(payload, lengths);

        return decode(parse.getData().array(),
                "AES/GCM/NoPadding",
                key,
                parse.getByteBufferMap().get("iv").array(),
                parse.getByteBufferMap().get("tag").array());
    }

    byte[] decode(byte[] input, String method, byte[] key, byte[] iv, byte[] tag) throws DecryptError {
        try {
            Cipher cipher = Cipher.getInstance(method);
            ByteBuffer buffer = ByteBuffer.allocate(input.length + tag.length);

            AlgorithmParameterSpec paramSpec = new GCMParameterSpec(tag.length * 8, iv);
            buffer.put(input);
            buffer.put(tag);

            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, paramSpec);

            return cipher.doFinal(buffer.array());
        } catch (Exception e) {
            throw new DecryptError("Decryption failed" + e);
        }
    }
}
