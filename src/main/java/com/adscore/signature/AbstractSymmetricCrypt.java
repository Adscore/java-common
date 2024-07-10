package com.adscore.signature;

import java.nio.ByteBuffer;
import java.util.Map;

import static com.adscore.signature.SignatureVerifierUtils.characterToInt;
import static com.adscore.signature.SignatureVerifierUtils.substrBuffer;


abstract class AbstractSymmetricCrypt {
    private Integer methodSize = 2;

    abstract byte[] decryptWithKey(ByteBuffer payload, byte[] key) throws DecryptError;

    DecryptResult parse(ByteBuffer payload, Map<String,Integer> lengths) throws DecryptError {

        if (payload.capacity() < methodSize + lengths.values().stream().reduce(0, Integer::sum).intValue()){
            throw new DecryptError("Premature data end");
        }

        int pos = methodSize;
        DecryptResult decryptResult = new DecryptResult();
        Map<String, Object> unpack = PhpUnpack.unpack("vmethod", substrBuffer(payload, 0, pos));
        decryptResult.setMethod(characterToInt(unpack.get("method")));

        for (Map.Entry<String, Integer> entry : lengths.entrySet()) {
            ByteBuffer bytesForKey = substrBuffer(payload, pos, entry.getValue());
            decryptResult.getByteBufferMap().put(entry.getKey(), bytesForKey);
            pos += entry.getValue();
        }

        decryptResult.setData(substrBuffer(payload, pos, null));
        return decryptResult;
    }

}
