package com.adscore.signature.v5.crypt;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

public class DecryptResult {
    private Integer method;
    private Map<String,ByteBuffer> byteBufferMap = new HashMap<>();
    private ByteBuffer data;

    public DecryptResult() {
    }

    public Integer getMethod() {
        return method;
    }

    public void setMethod(Integer method) {
        this.method = method;
    }

    public Map<String, ByteBuffer> getByteBufferMap() {
        return byteBufferMap;
    }

    public ByteBuffer getData() {
        return data;
    }

    public void setData(ByteBuffer data) {
        this.data = data;
    }
}
