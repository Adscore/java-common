package com.adscore.signature.v5;

import java.util.Map;

 class Signature5VerificationResult {
    private long zoneId;
    private Map<String,String> payload;
    private String error;

    public Signature5VerificationResult(Long zoneId, Map<String,String> payload) {
        this.zoneId = zoneId;
        this.payload = payload;
    }

     public Signature5VerificationResult(String error) {
         this.error = error;
     }

     public Long getZoneId() {
        return zoneId;
    }

    public Map<String, String> getPayload() {
        return payload;
    }
}
