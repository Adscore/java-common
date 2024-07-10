package com.adscore.signature;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

class DecryptResult {
    private Integer method;
    private Map<String,ByteBuffer> byteBufferMap = new HashMap<>();
    private ByteBuffer data;

    DecryptResult() {
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
