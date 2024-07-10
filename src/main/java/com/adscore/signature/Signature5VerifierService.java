package com.adscore.signature;


import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static com.adscore.signature.SignatureVerifierUtils.base64Decode;
import static com.adscore.signature.SignatureVerifierUtils.characterToInt;
import static com.adscore.signature.SignatureVerifierUtils.substr;
import static com.adscore.signature.SignatureVerifierUtils.substrBuffer;
import static com.adscore.signature.StructUnpacker.*;


class Signature5VerifierService {
    private final int version = 5;
    private final int headerLength = 11;

    Signature5VerifierService() {}

    Signature5VerificationResult createFromRequest(
            String signature,
            String userAgent,
            String key,
            List<String> ipAddresses) throws ParseError, VersionError, VerifyError {

        Map<String, String> parsed = parse(signature, base64Decode(key));
        verify(parsed, ipAddresses, userAgent);
        return Signature5ResponseMapper.mapToResponse(parsed);
    }


    private Map<String, String> parse(
            String signature,
            byte[] onCryptKeyRequest) throws SignatureParseError, StructParseError, DecryptError, VersionError {

        ByteBuffer payload = ByteBuffer.wrap(base64Decode(signature));

        if (payload.capacity() <= this.headerLength) {
            throw new SignatureParseError("Malformed signature");
        }

        Map<String, Object> unpack = PhpUnpack.unpack("Cversion/nlength/Jzone_id", payload);
        int length = characterToInt(unpack.get("length"));
        long zoneId = (Long) unpack.get("zone_id");

        if ((int) unpack.get("version") != this.version) {
            throw new VersionError("Invalid signature version");
        }

        ByteBuffer encryptedPayload = substrBuffer(payload, this.headerLength, length);

        if (encryptedPayload.capacity() < length) {
            throw new SignatureParseError("Truncated signature payload");
        }


        Map<String, String> decryptedPayload = decryptPayload(encryptedPayload, onCryptKeyRequest);
        decryptedPayload.put("zone_id", Long.toString(zoneId));
        return decryptedPayload;
    }


    private Map<String, String> decryptPayload(ByteBuffer payload, byte[] key) throws SignatureParseError, StructParseError, DecryptError {
        AbstractSymmetricCrypt crypt = CryptFactory.createFromPayload(payload);
        byte[] decryptedPayload = crypt.decryptWithKey(payload, key);

        Map<String, String> fromPayload = createFromPayload(ByteBuffer.wrap(decryptedPayload));
        return fromPayload;
    }

    private Map<String,String> createFromPayload(ByteBuffer decryptedPayload) throws StructParseError {
        String header = substr(new String(decryptedPayload.array(), StandardCharsets.UTF_8), 0, 1);
        switch (header) {
            case SERIALIZE_HEADER:
            case "Serialize":
            case "serialize":
                return serializeUnpack(decryptedPayload);
            case MSG_HEADER:
            case "Msgpack":
            case "msgpack":
                return msgUnpack(decryptedPayload);
            case JSON_HEADER:
            case "StructJson":
            case "json":
                return jsonUnpack(decryptedPayload);
            case RFC3986_HEADER:
            case "StructRfc3986":
            case "rfc3986":
                return rfc3986Unpack(decryptedPayload);
            default:
                throw new StructParseError("Unsupported struct class");
        }
    }

    private void verify(Map<String, String> parsed, List<String> ipAddresses, String userAgent) throws VerifyError {
        String matchingIp = null;

        for (String ipAddress : ipAddresses) {
            if (parsed.getOrDefault("ipv4.ip", null) != null) {
                if (ipAddress.equals(parsed.get("ipv4.ip"))){
                    matchingIp = ipAddress;
                    break;
                }
            }

            if (parsed.getOrDefault("ipv6.ip", null) != null) {
                if (IpV6Utils.abbreviate(parsed.get("ipv6.ip")).equals(IpV6Utils.abbreviate(ipAddress))){
                    matchingIp = ipAddress;
                    break;
                }
            }
        }

        if (matchingIp == null) {
            throw new VerifyError("Signature IP mismatch");
        }

        if (!parsed.get("b.ua").equals(userAgent)) {
            throw new VerifyError("Signature user agent mismatch");
        }

        if (!VerifierConstant.results.get(parsed.get("result")).equals(parsed.get("verdict"))){
            throw new VerifyError("Result mismatch");
        }
    }
}
