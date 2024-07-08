package com.adscore.signature.v5.utils;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class Utils {

    public static byte[] toByteArray(ByteBuffer buffer) {
        byte[] bytes = new byte[buffer.remaining()];
        buffer.get(bytes);
        return bytes;
    }

    public static int toInt(Object value){
        return (int)(short) value;
    }

    public static int strpos(String input, String searchFor, int offset) {
        if (input == null || searchFor == null) {
            return -1;
        }
        return input.indexOf(searchFor, offset);
    }

    public static String substr(String input, int offset, Integer length) {
        if (length != null) {
            return input.substring(offset, offset + length);
        }
        return input.substring(offset);
    }

    public static ByteBuffer substrBuffer(ByteBuffer input, int offset, Integer length) {
        if (length != null) {
            byte[] bytes = Arrays.copyOfRange(input.array(), offset, offset + length);
            return ByteBuffer.wrap(bytes);
        }
        return ByteBuffer.wrap(Arrays.copyOfRange(input.array(), offset, input.capacity()));
    }
}
