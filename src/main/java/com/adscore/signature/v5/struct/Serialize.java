package com.adscore.signature.v5.struct;

import com.adscore.signature.v5.errors.DecryptError;
import com.adscore.signature.v5.errors.StructParseError;
import com.adscore.signature.v5.utils.phputils.PhpUnserializer;
import com.adscore.signature.v5.utils.Utils;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static com.adscore.signature.v5.utils.Utils.substrBuffer;

public class Serialize {
    public static final String HEADER = "S";

    public static Map<String,String> unpack(ByteBuffer buffer) throws StructParseError {
        if (Utils.strpos(new String(buffer.array(), StandardCharsets.UTF_8), HEADER, 0) != 0){
            throw new StructParseError("Unexpected serializer type");
        }
        try {
            String payload = new String(substrBuffer(buffer, HEADER.length(), null).array(), StandardCharsets.UTF_8);
            return  (Map<String,String>) new PhpUnserializer(payload).unserialize();
        }catch (Exception e){
            throw new StructParseError("Error parsing Serialize struct: " + e);
        }
    }
}
