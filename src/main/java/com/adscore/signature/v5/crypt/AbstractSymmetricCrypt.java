package com.adscore.signature.v5.crypt;

import com.adscore.signature.v5.errors.DecryptError;
import com.adscore.signature.v5.utils.phputils.PhpUnpack;
import com.adscore.signature.v5.utils.Utils;

import java.nio.ByteBuffer;
import java.util.Map;

import static com.adscore.signature.v5.utils.Utils.substrBuffer;

public interface AbstractSymmetricCrypt {
    Integer METHOD_SIZE = 2;

    byte[] decryptWithKey(ByteBuffer payload, byte[] key) throws DecryptError;

    default DecryptResult parse(ByteBuffer payload, Map<String,Integer> lengths) throws DecryptError {

        if (payload.capacity() < METHOD_SIZE + lengths.values().stream().reduce(0, Integer::sum).intValue()){
            throw new DecryptError("Premature data end");
        }

        int pos = METHOD_SIZE;
        DecryptResult decryptResult = new DecryptResult();
        Map<String, Object> unpack = PhpUnpack.unpack("vmethod", substrBuffer(payload, 0, pos));
        decryptResult.setMethod(Utils.toInt(unpack.get("method")));

        for (Map.Entry<String, Integer> entry : lengths.entrySet()) {
            ByteBuffer bytesForKey = substrBuffer(payload, pos, entry.getValue());
            decryptResult.getByteBufferMap().put(entry.getKey(), bytesForKey);
            pos += entry.getValue();
        }

        decryptResult.setData(substrBuffer(payload, pos, null));
        return decryptResult;
    }

}
