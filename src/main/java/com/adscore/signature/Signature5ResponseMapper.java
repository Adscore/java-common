package com.adscore.signature;

import java.util.Map;

public class Signature5ResponseMapper {

    static Signature5VerificationResult mapToResponse(Map<String,String> result) {
        Signature5VerificationResult response = new Signature5VerificationResult();

        mapAndRemoveIfExists(result, response, "zone_id", Signature5VerificationResult::setZoneId);
        mapAndRemoveIfExists(result, response, "data", Signature5VerificationResult::setData);
        mapAndRemoveIfExists(result, response, "b.tzoffset", Signature5VerificationResult::setTzOffset);
        mapAndRemoveIfExists(result, response, "HsignatureTime", Signature5VerificationResult::setSignatureTime);
        mapAndRemoveIfExists(result, response, "b.sr.w", Signature5VerificationResult::setHorizontalResolution);
        mapAndRemoveIfExists(result, response, "result", Signature5VerificationResult::setResult);
        mapAndRemoveIfExists(result, response, "b.truech.model", Signature5VerificationResult::setTruechModel);
        mapAndRemoveIfExists(result, response, "b.truech.platform.v", Signature5VerificationResult::setPlatformV);
        mapAndRemoveIfExists(result, response, "b.truech.arch", Signature5VerificationResult::setTruechArch);
        mapAndRemoveIfExists(result, response, "b.platform", Signature5VerificationResult::setbPlatform);
        mapAndRemoveIfExists(result, response, "b.platform.v", Signature5VerificationResult::setTruechPlatformV);
        mapAndRemoveIfExists(result, response, "b.gpu", Signature5VerificationResult::setGpu);
        mapAndRemoveIfExists(result, response, "b.sr.h", Signature5VerificationResult::setVerticalResolution);
        mapAndRemoveIfExists(result, response, "b.truech.mobile", Signature5VerificationResult::setTruechMobile);
        mapAndRemoveIfExists(result, response, "b.cpucores", Signature5VerificationResult::setCpuCores);
        mapAndRemoveIfExists(result, response, "ipv4.v", Signature5VerificationResult::setIpv4V);
        mapAndRemoveIfExists(result, response, "ipv6.v", Signature5VerificationResult::setIpv6V);
        mapAndRemoveIfExists(result, response, "b.truech.bitness", Signature5VerificationResult::setTruechBitness);
        mapAndRemoveIfExists(result, response, "b.trueloc.c", Signature5VerificationResult::setTrueUaLocation);
        mapAndRemoveIfExists(result, response, "sub_id", Signature5VerificationResult::setSubId);
        mapAndRemoveIfExists(result, response, "b.trueua", Signature5VerificationResult::setTrueUa);
        mapAndRemoveIfExists(result, response, "b.truech.ua", Signature5VerificationResult::setTruechUa);
        mapAndRemoveIfExists(result, response, "b.ram", Signature5VerificationResult::setRam);
        mapAndRemoveIfExists(result, response, "requestTime", Signature5VerificationResult::setRequestTime);
        mapAndRemoveIfExists(result, response, "b.truech.full.v", Signature5VerificationResult::setTruechFullV);
        mapAndRemoveIfExists(result, response, "ipv4.ip", Signature5VerificationResult::setIpv4Ip);
        mapAndRemoveIfExists(result, response, "b.ua", Signature5VerificationResult::setVisitorUserAgent);
        mapAndRemoveIfExists(result, response, "verdict", Signature5VerificationResult::setVerdict);
        mapAndRemoveIfExists(result, response, "b.truech.platform", Signature5VerificationResult::setTruechPlatform);
        mapAndRemoveIfExists(result, response, "signatureTime", Signature5VerificationResult::setSignatureTime);
        mapAndRemoveIfExists(result, response, "ipv6.ip", Signature5VerificationResult::setIpv6Ip);
        mapAndRemoveIfExists(result, response, "token.c", Signature5VerificationResult::setToken);
        mapAndRemoveIfExists(result, response, "b.applesense", Signature5VerificationResult::setAppleSense);

        if (!result.isEmpty()){
            response.setAdditionalData(result);
        }
        return response;
    }

    private static  <T> void mapAndRemoveIfExists(Map<String, String> map, Signature5VerificationResult myClass, String key, Setter<T> setter) {
        if (map.containsKey(key)) {
            try {
                setter.set(myClass, (T) map.get(key));
                map.remove(key);
            } catch (Exception e){
                // Error during parse. Continue the process, the item will be added to additionalData
            }
        }
    }
}

@FunctionalInterface
interface Setter<T> {
    void set(Signature5VerificationResult myClass, T value);
}
