package com.adscore.signature;


import java.util.Map;

/**
 * Representation of signature verification results
 *
 */
 public class Signature5VerificationResult {
     /**
      * Zone-id
      */
     private Long zoneId;
     /**
      * Detection result as number, one of following: 0, 3, 6, 9
      */
     private Integer result;

     /**
      * Detection result as text, one of following: ok, junk, proxy, bot
      */
     private String verdict;

     /**
      * Visitor's User Agent
      */
     private String visitorUserAgent;

    /**
     * Data
     */
    private String data;

     /**
      * IPv4 address
      */
     private String ipv4Ip;

     /**
      * Number of bytes required for IP matching
      */
     private Integer ipv4V;

     /**
      * IPv6 address
      */
     private String ipv6Ip;

     /**
      * Number of left-most bytes of IPv6 address needed to match
      */
     private Integer ipv6V;

     /**
      * Number of CPU logical cores gathered from navigator.hardwareConcurrency
      */
     private Integer cpuCores;

     /**
      * Amount of RAM memory in GB gathered from navigator.deviceMemory
      */
     private Integer ram;

     /**
      * Timezone offset from GMT in minutes
      */
     private Integer tzOffset;

     /**
      * User-Agent Client Hints Platform
      */
     private String bPlatform;

     /**
      * Content of Sec-CH-UA-Platform-Version request header
      */
     private String platformV;

     /**
      * GPU Model obtained from WebGL and WebGPU APIs
      */
     private String gpu;

     /**
      * Detected iPhone/iPad model by Adscore AppleSense
      */
     private String appleSense;

     /**
      * Physical screen horizontal resolution
      */
     private Integer horizontalResolution;

     /**
      * Physical screen vertical resolution
      */
     private Integer verticalResolution;

     /**
      * Adscore TrueUA-enriched User-Agent
      */
     private String trueUa;

     /**
      * Adscore True Location Country
      */
     private String trueUaLocationC;

     /**
      * Adscore True Location Confidence
      */
     private Integer trueUaLoactionS;

     /**
      * Adscore TrueUA-enriched Client Hints header Sec-CH-UA
      */
     private String truechUa;

     /**
      * Adscore TrueUA-enriched Client Hints header Sec-CH-UA-Arch
      */
     private String truechArch;

     /**
      * Adscore TrueUA-enriched Client Hints header Sec-CH-UA-Bitness
      */
     private Integer truechBitness;

     /**
      * Adscore TrueUA-enriched Client Hints header Sec-CH-UA-Model
      */
     private String truechModel;

     /**
      * Adscore TrueUA-enriched Client Hints header Sec-CH-UA-Platform
      */
     private String truechPlatform;

     /**
      * Adscore TrueUA-enriched Client Hints header Sec-CH-UA-Platform-Version
      */
     private String truechPlatformV;

     /**
      * Adscore TrueUA-enriched Client Hints header Sec-CH-UA-Full-Version
      */
     private String truechFullV;

     /**
      * Adscore TrueUA-enriched Client Hints header Sec-CH-UA-Mobile
      */
     private String truechMobile;

     /**
      * Indicates whether visitor is using Private Browsing (Incognito) Mode
      */
     private String incognito;

    /**
     * Adscore zone subId
     */
     private String subId;

    /**
     * Request time
     */
     private Long requestTime;

    /**
     * Signature time
     */
     private Long signatureTime;

    /**
     * Token
     */
     private String token;

    /**
      * Other, which has not been mapped to a field, or getting error during parsing
      */
     private Map<String,String> additionalData;


     Signature5VerificationResult() {}

    /**
     * PROTECTED SETTERS WITH TYPE CONVERSION IF NEED
     */

     void setZoneId(String zoneId) {
         this.zoneId = Long.valueOf(zoneId);
     }

    void setSignatureTime(String signatureTime) {
        this.signatureTime = Long.valueOf(signatureTime);
    }

    void setSubId(String subId) {
        this.subId = subId;
    }

    void setRequestTime(String requestTime) {
        this.requestTime = Long.valueOf(requestTime);
    }

    void setResult(String result) {
        this.result = Integer.parseInt(result);
    }

    void setVerdict(String verdict) {
        this.verdict = verdict;
    }

    void setVisitorUserAgent(String visitorUserAgent) {
        this.visitorUserAgent = visitorUserAgent;
    }

    void setIpv4Ip(String ipv4Ip) {
        this.ipv4Ip = ipv4Ip;
    }

    void setIpv4V(String ipv4V) {
        this.ipv4V = Integer.parseInt(ipv4V);
    }

    void setIpv6V(String ipv6V) {
        this.ipv6V = Integer.parseInt(ipv6V);
    }

    void setCpuCores(String cpuCores) {
        this.cpuCores = Integer.parseInt(cpuCores);
    }

    void setRam(String ram) {
        this.ram = Integer.parseInt(ram);
    }

    void setTzOffset(String tzOffset) {
        this.tzOffset = Integer.parseInt(tzOffset);
    }

    void setbPlatform(String bPlatform) {
        this.bPlatform = bPlatform;
    }

    void setPlatformV(String platformV) {
        this.platformV = platformV;
    }

    void setGpu(String gpu) {
        this.gpu = gpu;
    }

    void setAppleSense(String appleSense) {
        this.appleSense = appleSense;
    }

    void setHorizontalResolution(String horizontalResolution) {
        this.horizontalResolution = Integer.parseInt(horizontalResolution);
    }

    void setVerticalResolution(String verticalResolution) {
        this.verticalResolution = Integer.parseInt(verticalResolution);
    }

    void setTrueUa(String trueUa) {
        this.trueUa = trueUa;
    }

    void setTrueUaLocationC(String trueUaLocationC) {
        this.trueUaLocationC = trueUaLocationC;
    }

    void setTrueUaLoactionS(String trueUaLoactionS) {
        this.trueUaLoactionS = Integer.parseInt(trueUaLoactionS);
    }

    void setTruechUa(String truechUa) {
        this.truechUa = truechUa;
    }

    void setTruechArch(String truechArch) {
        this.truechArch = truechArch;
    }

    void setTruechBitness(String truechBitness) {
        this.truechBitness = Integer.parseInt(truechBitness);
    }

    void setTruechModel(String truechModel) {
        this.truechModel = truechModel;
    }

    void setTruechPlatform(String truechPlatform) {
        this.truechPlatform = truechPlatform;
    }

    void setTruechPlatformV(String truechPlatformV) {
        this.truechPlatformV = truechPlatformV;
    }

    void setTruechFullV(String truechFullV) {
        this.truechFullV = truechFullV;
    }

    void setTruechMobile(String truechMobile) {
        this.truechMobile = truechMobile;
    }

    void setIncognito(String incognito) {
        this.incognito = incognito;
    }

    void setAdditionalData(Map<String, String> additionalData) {
        this.additionalData = additionalData;
    }

    void setData(String data) {
        this.data = data;
    }

    void setToken(String token) {
        this.token = token;
    }

    void setIpv6Ip(String ipv6) {
        this.ipv6Ip = ipv6Ip;
    }


    /**
     * PUBLIC GETTERS
     */

    public String getToken() {
        return token;
    }

    public Long getZoneId() {
        return zoneId;
    }

    public Integer getResult() {
        return result;
    }

    public String getVerdict() {
        return verdict;
    }

    public String getVisitorUserAgent() {
        return visitorUserAgent;
    }

    public String getData() {
        return data;
    }

    public String getIpv4Ip() {
        return ipv4Ip;
    }

    public Integer getIpv4V() {
        return ipv4V;
    }

    public String getIpv6Ip() {
        return ipv6Ip;
    }

    public Integer getIpv6V() {
        return ipv6V;
    }

    public Integer getCpuCores() {
        return cpuCores;
    }

    public Integer getRam() {
        return ram;
    }

    public Integer getTzOffset() {
        return tzOffset;
    }

    public String getbPlatform() {
        return bPlatform;
    }

    public String getPlatformV() {
        return platformV;
    }

    public String getGpu() {
        return gpu;
    }

    public String getAppleSense() {
        return appleSense;
    }

    public Integer getHorizontalResolution() {
        return horizontalResolution;
    }

    public Integer getVerticalResolution() {
        return verticalResolution;
    }

    public String getTrueUa() {
        return trueUa;
    }

    public String getTrueUaLocationC() {
        return trueUaLocationC;
    }

    public Integer getTrueUaLoactionS() {
        return trueUaLoactionS;
    }

    public String getTruechUa() {
        return truechUa;
    }

    public String getTruechArch() {
        return truechArch;
    }

    public int getTruechBitness() {
        return truechBitness;
    }

    public String getTruechModel() {
        return truechModel;
    }

    public String getTruechPlatform() {
        return truechPlatform;
    }

    public String getTruechPlatformV() {
        return truechPlatformV;
    }

    public String getTruechFullV() {
        return truechFullV;
    }

    public String getTruechMobile() {
        return truechMobile;
    }

    public String getIncognito() {
        return incognito;
    }

    public String getSubId() {
        return subId;
    }

    public Long getRequestTime() {
        return requestTime;
    }

    public Long getSignatureTime() {
        return signatureTime;
    }

    public Map<String, String> getAdditionalData() {
        return additionalData;
    }
}
