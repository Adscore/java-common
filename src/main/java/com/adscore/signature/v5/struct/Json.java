package com.adscore.signature.v5.struct;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import com.adscore.signature.v5.errors.DecryptError;
import com.adscore.signature.v5.errors.StructParseError;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;


public class Json {
    public static final String HEADER = "J";

    public static Map<String, String> unpack(ByteBuffer payload) throws StructParseError {
        try {
            String strPayload  = new String(payload.array(), StandardCharsets.UTF_8);
            String substring = strPayload.substring(1,strPayload.length());
            return new ObjectMapper().readValue(substring, new TypeReference<Map<String, String>>() {});
        } catch (JsonProcessingException e) {
            throw new StructParseError("Error parsing Json struct: " + e);
        }
    }
}
