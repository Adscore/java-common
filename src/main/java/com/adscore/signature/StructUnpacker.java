package com.adscore.signature;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.msgpack.core.MessagePack;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

class StructUnpacker {
    static final String SERIALIZE_HEADER = "S";
    static final String JSON_HEADER = "J";
    static final String MSG_HEADER = "M";
    static final String RFC3986_HEADER = "H";


    static Map<String,String> serializeUnpack(ByteBuffer buffer) throws StructParseError {
        if (SignatureVerifierUtils.strpos(new String(buffer.array(), StandardCharsets.UTF_8), SERIALIZE_HEADER, 0) != 0){
            throw new StructParseError("Unexpected serializer type");
        }
        try {
            String payload = new String(SignatureVerifierUtils.substrBuffer(buffer, SERIALIZE_HEADER.length(), null).array(), StandardCharsets.UTF_8);
            return  (Map<String,String>) new PhpUnserializer(payload).unserialize();
        }catch (Exception e){
            throw new StructParseError("Error parsing Serialize struct: " + e);
        }
    }

    static Map<String, String> jsonUnpack(ByteBuffer payload) throws StructParseError {
        try {
            String strPayload  = new String(payload.array(), StandardCharsets.UTF_8);
            String substring = strPayload.substring(1,strPayload.length());
            return new ObjectMapper().readValue(substring, new TypeReference<Map<String, String>>() {});
        } catch (JsonProcessingException e) {
            throw new StructParseError("Error parsing StructJson struct: " + e);
        }
    }

    static Map<String,String> msgUnpack(ByteBuffer buffer) throws StructParseError {
        try {
            ByteBuffer slice = buffer.position(1).slice();
            String unpacked = new MessagePack.UnpackerConfig()
                    .withStringDecoderBufferSize(16 * 1024).newUnpacker(slice).unpackValue().toString();
            return new ObjectMapper().readValue(unpacked, new TypeReference<Map<String, String>>() {});
        } catch (Exception e) {
            throw new StructParseError("Error parsing MsgPack struct: " + e);
        }
    }

    static Map<String, String> rfc3986Unpack(ByteBuffer data) throws StructParseError {
        try {
            data.position(1).slice();
            String queryString = StandardCharsets.UTF_8.decode(data).toString();
            String decoded = decodeUrl(queryString);
            String[] pairs = decoded.split("&");
            Map<String, String> result = new HashMap<>();

            for (String pair : pairs) {
                String[] keyValue = pair.split("=", 2);
                if (keyValue.length == 2) {
                    result.put(keyValue[0], keyValue[1]);
                } else {
                    result.put(keyValue[0], "");
                }
            }
            return result;
        }catch (Exception e){
            throw new StructParseError("Error parsing StructRfc3986 struct: " + e);
        }
    }

    private static String decodeUrl(String encodedUrl) {
        StringBuilder decodedUrl = new StringBuilder();
        int len = encodedUrl.length();
        int i = 0;

        while (i < len) {
            char c = encodedUrl.charAt(i);
            if (c == '%') {
                if (i + 2 < len) {
                    String hex = encodedUrl.substring(i + 1, i + 3);
                    try {
                        char decodedChar = (char) Integer.parseInt(hex, 16);
                        decodedUrl.append(decodedChar);
                        i += 3;
                    } catch (NumberFormatException e) {
                        decodedUrl.append(c);
                        i++;
                    }
                } else {
                    decodedUrl.append(c);
                    i++;
                }
            } else {
                decodedUrl.append(c);
                i++;
            }
        }

        return decodedUrl.toString();
    }

}
