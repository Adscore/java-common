package com.adscore.signature.v5.crypt;


public enum CryptMethod {
    AES_128_GCM(12),
    AES_192_GCM(12),
    AES_256_GCM(12),

    AES_128_CBC(16),
    AES_192_CBC(16),
    AES_256_CBC(16),
    ;

    private final int ivLength;

    CryptMethod(int ivLength) {
        this.ivLength = ivLength;
    }

    public int getIvLength() {
        return ivLength;
    }
}
