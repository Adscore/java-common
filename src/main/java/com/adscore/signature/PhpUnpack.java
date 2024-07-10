package com.adscore.signature;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.HashMap;
import java.util.Map;

import static com.adscore.signature.SignatureVerifierUtils.toByteArray;

/**
 * Java implementation PHP Unpack() for
 * unpacking data from binary string
 */

class PhpUnpack {
    private static final String NAME = "name";
    private static final String CODE = "code";

    static Map<String, Object> unpack(String format, ByteBuffer input) {
        String[] instructions = format.split("/");

        Map<String, Object> result = new HashMap<>();

        for (String instruction : instructions) {
            Map<String, String> codeAndName = getCodeAndName(instruction);

            String code = codeAndName.get(CODE);
            String name = codeAndName.get(NAME);

            DecodedData decodedData = decode(input, code);
            result.put(name, decodedData.decodedData);
        }
        return result;
    }

    private static DecodedData decode(ByteBuffer input, String code) {
        Object decodedData;
        if (!input.hasRemaining()) {
            throw new IllegalArgumentException("Buffer underflow. No more data to read.");
        }
        int bytesOffset;

        switch (code) {
            case "c":
                decodedData = input.get();
                bytesOffset = 1;
                break;
            case "C":
                decodedData = input.get() & 0xFF;
                bytesOffset = 1;
                break;
            case "n":
                decodedData = input.getShort();
                bytesOffset = 2;
                break;
            case "N":
                decodedData = input.getInt();
                bytesOffset = 4;
                break;
            case "J":
                decodedData = input.getLong();
                bytesOffset = 8;
                break;
            case "v":
                decodedData = input.order(ByteOrder.LITTLE_ENDIAN).getShort();
                bytesOffset = 2;
                break;
            default:
                throw new IllegalArgumentException("Unrecognized instruction: " + code);
        }
        return new DecodedData(bytesOffset,decodedData);
    }

    static byte[] pack(String format, Number... inputs) {
        String[] instructions = format.split("");

        if (instructions.length != inputs.length) {
            throw new IllegalArgumentException(
                    "Invalid format length, expected " + inputs.length + " number of codes"
            );
        }

        ByteBuffer result = ByteBuffer.allocate(1024).order(ByteOrder.BIG_ENDIAN);

        for (int i = 0; i < inputs.length; i++) {
            String code = instructions[i];
            ByteBuffer encodedData = encode(inputs[i], code);
            result.put(encodedData);
        }

        result.flip();
        return toByteArray(result);
    }


    private static ByteBuffer encode(Number input, String code) {
        ByteBuffer buffer;
        switch (code) {
            case "c":
                buffer = ByteBuffer.allocate(1);
                buffer.put(input.byteValue());
                break;
            case "C":
                buffer = ByteBuffer.allocate(1);
                buffer.put((byte) (input.intValue() & 0xFF));
                break;
            case "n":
                buffer = ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN);
                buffer.putShort(input.shortValue());
                break;
            case "N":
                buffer = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
                buffer.putInt(input.intValue());
                break;
            case "J":
                buffer = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN);
                buffer.putLong(input.longValue());
                break;
            case "v":
                buffer = ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN);
                buffer.putShort(input.shortValue());
                break;
            default:
                throw new IllegalArgumentException("Unrecognized instruction: " + code);
        }
        buffer.flip();
        return buffer;
    }

    private static Map<String, String> getCodeAndName(String instruction) {
        if (instruction == null || instruction.length() == 0) {
            throw new IllegalArgumentException("Empty instruction");
        }

        Map<String, String> result = new HashMap<>();
        result.put(CODE, instruction.substring(0, 1));
        result.put(NAME, instruction.substring(1));
        return result;
    }
}

 class DecodedData {
    int bytesOffset;
    Object decodedData;

    DecodedData(int bytesOffset, Object decodedData) {
        this.bytesOffset = bytesOffset;
        this.decodedData = decodedData;
    }

     int getBytesOffset() {
         return bytesOffset;
     }

     Object getDecodedData() {
         return decodedData;
     }
 }
