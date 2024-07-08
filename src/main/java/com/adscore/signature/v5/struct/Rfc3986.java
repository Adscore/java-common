package com.adscore.signature.v5.struct;

import com.adscore.signature.v5.errors.StructParseError;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class Rfc3986 {
    public static final String HEADER = "H";

    public static Map<String, String> unpack(ByteBuffer data) throws StructParseError {
        try {
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
            throw new StructParseError("Error parsing Rfc3986 struct: " + e);
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
