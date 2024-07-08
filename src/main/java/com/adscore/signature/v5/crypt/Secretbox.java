package com.adscore.signature.v5.crypt;
import com.adscore.signature.v5.errors.DecryptError;
import org.abstractj.kalium.crypto.SecretBox;

import java.nio.ByteBuffer;
import java.util.HashMap;

public class Secretbox implements AbstractSymmetricCrypt {
    public static final int METHOD = 0x0101;

    @Override
    public byte[] decryptWithKey(ByteBuffer payload, byte[] key) throws DecryptError {
        int nonceBytes = 24;
        DecryptResult parse = this.parse(payload, new HashMap() {{
            put("iv", nonceBytes);
        }});
        SecretBox secretBox = new SecretBox(key);
        return secretBox.decrypt(parse.getByteBufferMap().get("iv").array(), parse.getData().array());
    }
}
