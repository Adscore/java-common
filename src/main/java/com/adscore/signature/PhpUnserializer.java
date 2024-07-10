package com.adscore.signature;

import java.util.HashMap;
import java.util.Map;

class PhpUnserializer {
    private String data;
    private int index;

    PhpUnserializer(String data) {
        this.data = data;
        this.index = 0;
    }

    Object unserialize() {
        char type = data.charAt(index);
        index += 2;

        switch (type) {
            case 'i':
                return parseInt();
            case 'd':
                return parseFloat();
            case 'b':
                return parseBoolean();
            case 's':
                return parseString();
            case 'a':
                return parseArray();
            case 'O':
                return parseObject();
            default:
                throw new IllegalArgumentException("PhpUnserializer error. Unsupported type: " + type);
        }
    }

    private String parseInt() {
        int semiColonIndex = data.indexOf(';', index);
        String intStr = data.substring(index, semiColonIndex);
        index = semiColonIndex + 1;
        return intStr;
    }

    private String parseFloat() {
        int semiColonIndex = data.indexOf(';', index);
        String floatStr = data.substring(index, semiColonIndex);
        index = semiColonIndex + 1;
        return floatStr;
    }

    private String parseBoolean() {
        char boolChar = data.charAt(index);
        index += 2;
        return boolChar == '1' ? "true" : "false";
    }

    private String parseString() {
        int colonIndex = data.indexOf(':', index);
        int length = Integer.parseInt(data.substring(index, colonIndex));
        index = colonIndex + 2;
        String str = data.substring(index, index + length);
        index += length + 2;
        return str;
    }


    private Map<Object, Object> parseArray() {
        int colonIndex = data.indexOf(':', index);
        int length = Integer.parseInt(data.substring(index, colonIndex));
        index = colonIndex + 2;
        Map<Object, Object> map = new HashMap<>();
        for (int i = 0; i < length; i++) {
            Object key = unserialize();
            Object value = unserialize();
            map.put(key, value);
        }
        index++;
        return map;
    }

    private Map<String, Object> parseObject() {
        int colonIndex = data.indexOf(':', index);
        int classNameLength = Integer.parseInt(data.substring(index, colonIndex));
        index = colonIndex + 2;
        String className = data.substring(index, index + classNameLength);
        index += classNameLength + 2;

        colonIndex = data.indexOf(':', index);
        int length = Integer.parseInt(data.substring(index, colonIndex));
        index = colonIndex + 2;
        Map<String, Object> fields = new HashMap<>();
        for (int i = 0; i < length; i++) {
            String key = (String) unserialize();
            Object value = unserialize();
            fields.put(key, value);
        }
        index++;

        return fields;
    }

}
