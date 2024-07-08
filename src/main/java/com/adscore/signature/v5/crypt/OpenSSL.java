package com.adscore.signature.v5.crypt;

import com.adscore.signature.v5.errors.DecryptError;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;
import java.util.HashMap;

public class OpenSSL implements AbstractSymmetricCrypt {
    public static final int METHOD = 0x0200;

    private CryptMethod method = CryptMethod.AES_256_CBC;
    private String algo = "sha256";

    public OpenSSL() {
    }


    public byte[] key(String password, String salt) throws NoSuchAlgorithmException, InvalidKeyException {
        if (salt == null) {
            MessageDigest digest = MessageDigest.getInstance(this.algo);
            return Base64.getDecoder().decode(Base64.getEncoder().encodeToString(digest.digest(password.getBytes(StandardCharsets.UTF_8))));
        }

        Mac mac = Mac.getInstance(this.algo);
        mac.init(new SecretKeySpec(salt.getBytes(StandardCharsets.UTF_8), this.algo));
        return Base64.getDecoder().decode(Base64.getEncoder().encodeToString(mac.doFinal(password.getBytes(StandardCharsets.UTF_8))));
    }



     public byte[] decryptWithKey(ByteBuffer payload, byte[] key) throws DecryptError {
        HashMap<String, Integer> lengths = new HashMap(){{put("iv", method.getIvLength());}};
        DecryptResult result = this.parse(payload, lengths);

        if (result.getMethod() != OpenSSL.METHOD) {
            throw new DecryptError("Unrecognized payload");
        }

        return this.decode(result.getData().array(), "AES/CBC/PKCS5Padding", key, result.getByteBufferMap().get("iv").array());
    }

    private byte[] decode(byte[] input, String method, byte[] key, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance(method);
            ByteBuffer buffer = ByteBuffer.allocate(input.length);

            AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
            buffer.put(input);

            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, paramSpec);

            return cipher.doFinal(buffer.array());
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }
}
