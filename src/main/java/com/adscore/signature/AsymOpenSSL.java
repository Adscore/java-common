package com.adscore.signature;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

class AsymOpenSSL {
    private String algorithm;

    public AsymOpenSSL(String algorithm) {
        this.algorithm = algorithm;
    }

    boolean verify(String data, String token, byte[] publicKey) throws VerifyError {
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PublicKey pubKey = keyFactory.generatePublic(keySpec);

            byte[] decodedData = Base64.getMimeDecoder().decode(data);
            byte[] signInputBytes = token.getBytes(StandardCharsets.ISO_8859_1);
            Signature sig = Signature.getInstance(this.algorithm);
            sig.initVerify(pubKey);
            sig.update(decodedData);
            return sig.verify(signInputBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new VerifyError("wrong algorithm: " +e.getMessage());
        } catch (InvalidKeySpecException e) {
            throw new VerifyError("invalid spec key: " +e.getMessage());
        } catch (SignatureException e) {
            throw new VerifyError("signature verify error: " +e.getMessage());
        } catch (InvalidKeyException e) {
            throw new VerifyError("invalid key: " +e.getMessage());
        }
    }
}
