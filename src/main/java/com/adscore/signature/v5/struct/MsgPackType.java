package com.adscore.signature.v5.struct;

import com.adscore.signature.v5.errors.StructParseError;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.msgpack.core.MessagePack;
import java.nio.ByteBuffer;
import java.util.Map;

public class MsgPackType {
    public static final String HEADER = "M";

    public static Map<String,String> unpack(ByteBuffer buffer) throws StructParseError {
        try {
            ByteBuffer slice = buffer.position(1).slice();
            String unpacked = new MessagePack.UnpackerConfig()
                    .withStringDecoderBufferSize(16 * 1024).newUnpacker(slice).unpackValue().toString();
            return new ObjectMapper().readValue(unpacked, new TypeReference<Map<String, String>>() {});
        } catch (Exception e) {
            throw new StructParseError("Error parsing MsgPack struct: " + e);
        }
    }

}
