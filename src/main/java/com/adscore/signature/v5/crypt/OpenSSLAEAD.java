package com.adscore.signature.v5.crypt;

import com.adscore.signature.v5.errors.DecryptError;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.spec.AlgorithmParameterSpec;
import java.util.LinkedHashMap;
import java.util.Map;

public class OpenSSLAEAD implements AbstractSymmetricCrypt{
    public static final int METHOD = 0x0201;
    private CryptMethod method = CryptMethod.AES_256_GCM;

    public OpenSSLAEAD() {
    }

    public byte[] decryptWithKey(ByteBuffer payload, byte[] key) throws DecryptError {
        Map<String,Integer> lengths = new LinkedHashMap(){{
            put("iv", method.getIvLength());
            put("tag", 16);
        }};

        DecryptResult parse = this.parse(payload, lengths);
        byte[] decode = decode(parse.getData().array(), "AES/GCM/NoPadding", key, parse.getByteBufferMap().get("iv").array(), parse.getByteBufferMap().get("tag").array());
        return decode;
    }

    protected byte[] decode(byte[] input, String method, byte[] key, byte[] iv, byte[] tag) {
        try {
            Cipher cipher = Cipher.getInstance(method);
            AlgorithmParameterSpec paramSpec = null;
            ByteBuffer buffer = ByteBuffer.allocate(input.length + tag.length);

            paramSpec = new GCMParameterSpec(tag.length * 8, iv);
            buffer.put(input);
            buffer.put(tag);

            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, paramSpec);

            return cipher.doFinal(buffer.array());
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }
}
