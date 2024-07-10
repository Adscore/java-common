package com.adscore.signature;
import org.abstractj.kalium.crypto.SecretBox;

import java.nio.ByteBuffer;
import java.util.HashMap;

class Secretbox extends AbstractSymmetricCrypt {
    static final int METHOD = 0x0101;

    @Override
    byte[] decryptWithKey(ByteBuffer payload, byte[] key) throws DecryptError {
        int nonceBytes = 24;
        DecryptResult parse = this.parse(payload, new HashMap() {{
            put("iv", nonceBytes);
        }});
        SecretBox secretBox = new SecretBox(key);
        return secretBox.decrypt(parse.getByteBufferMap().get("iv").array(), parse.getData().array());
    }
}
