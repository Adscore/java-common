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

    public boolean verify(String data, String signature, String publicKey) throws VerifyError {
        try {
            Signature sig = Signature.getInstance(this.algorithm);

            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            byte[] keyBytes = Base64.getDecoder().decode(publicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            PublicKey pubKey = keyFactory.generatePublic(keySpec);

            sig.initVerify(pubKey);
            sig.update(data.getBytes());

            byte[] signatureBytes = signature.getBytes(StandardCharsets.ISO_8859_1);

            return sig.verify(signatureBytes);

        } catch (NoSuchAlgorithmException e) {
            throw new VerifyError("wrong algorithm: " + e.getMessage());
        } catch (InvalidKeySpecException e) {
            throw new VerifyError("invalid spec key: " + e.getMessage());
        } catch (SignatureException e) {
            throw new VerifyError("signature verify error: " + e.getMessage());
        } catch (InvalidKeyException e) {
            throw new VerifyError("invalid key: " + e.getMessage());
        }
    }

}
