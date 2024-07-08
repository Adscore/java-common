package com.adscore.signature.v5;

import com.adscore.signature.v5.errors.DecryptError;
import com.adscore.signature.v5.errors.SignatureParseError;
import com.adscore.signature.v5.crypt.AbstractSymmetricCrypt;
import com.adscore.signature.v5.crypt.CryptFactory;
import com.adscore.signature.v5.errors.StructParseError;
import com.adscore.signature.v5.utils.phputils.PhpUnpack;
import com.adscore.signature.v5.struct.*;
import com.adscore.signature.v5.utils.Base64Util;
import com.adscore.signature.v5.utils.Utils;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.adscore.signature.v5.utils.Utils.substr;
import static com.adscore.signature.v5.utils.Utils.substrBuffer;

class Signature5Service {
    private final int version = 5;
    private final int headerLength = 11;
    private static final HashMap<String, String> results =
            new HashMap<String, String>() {
                {
                    put("0", "ok");
                    put("3", "junk");
                    put("6", "proxy");
                    put("9", "bot");
                }
            };

    public Signature5Service() {
    }

    public Signature5VerificationResult createFromRequest(
            String signature,
            String userAgent,
            String key,
            List<String> ipAddresses) {
        try {
            Signature5VerificationResult parsed = parse(signature, Base64Util.base64Decode(key));
            verify(parsed, ipAddresses, userAgent);
            return parsed;
        } catch (Exception e) {
            return new Signature5VerificationResult(e.getMessage());
        }
    }


    private void verify(Signature5VerificationResult parsed, List<String> ipAddresses, String userAgent) throws VerifyError {
        String matchingIp = null;
        Map<String, String> payload = parsed.getPayload();

        for (String ipAddress : ipAddresses) {
            byte[] nIpAddress = ipAddress.getBytes();

            if (payload.getOrDefault("ipv4.ip", null) != null) {
                if (Arrays.equals(nIpAddress, payload.get("ipv4.ip").getBytes())){
                    matchingIp = ipAddress;
                    break;
                }
            }

            if (payload.getOrDefault("ipv6.ip", null) != null) {
                if (Arrays.equals(nIpAddress, payload.get("ipv4.ip").getBytes())){
                    matchingIp = ipAddress;
                    break;
                }
            }
        }

        if (matchingIp == null) {
            throw new VerifyError("Signature IP mismatch");
        }


        if (!payload.get("b.ua").equals(userAgent)) {
            throw new VerifyError("Signature user agent mismatch");
        }

        if (!results.get(payload.get("result")).equals(payload.get("verdict"))){
            throw new VerifyError("Result mismatch");
        }
    }

    private Signature5VerificationResult parse(String signature, byte[] onCryptKeyRequest) throws SignatureParseError, StructParseError, DecryptError {
        ByteBuffer payload = ByteBuffer.wrap(Base64Util.base64Decode(signature));

        if (payload.capacity() <= this.headerLength) {
            throw new SignatureParseError("Malformed signature");
        }

        Map<String, Object> unpack = PhpUnpack.unpack("Cversion/nlength/Jzone_id", payload);
        int length = Utils.toInt(unpack.get("length"));
        long zoneId = (Long) unpack.get("zone_id");

        if ((int) unpack.get("version") != this.version) {
            throw new SignatureParseError("Invalid signature version");
        }

        ByteBuffer encryptedPayload = substrBuffer(payload, this.headerLength, length);

        if (encryptedPayload.capacity() < length) {
            throw new SignatureParseError("Truncated signature payload");
        }


        Map<String, String> decryptedPayload = decryptPayload(encryptedPayload, onCryptKeyRequest);
        return new Signature5VerificationResult(zoneId, decryptedPayload);
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
            case Serialize.HEADER:
            case "Serialize":
            case "serialize":
                return Serialize.unpack(decryptedPayload);
            case MsgPackType.HEADER:
            case "Msgpack":
            case "msgpack":
                return MsgPackType.unpack(decryptedPayload);
            case Json.HEADER:
            case "Json":
            case "json":
                return Json.unpack(decryptedPayload);
            case Rfc3986.HEADER:
            case "Rfc3986":
            case "rfc3986":
                return Rfc3986.unpack(decryptedPayload);
            default:
                throw new StructParseError("Unsupported struct class");
        }
    }
}
