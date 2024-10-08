
package com.adscore.signature;


import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static com.adscore.signature.SignatureVerifierUtils.base64Decode;
import static com.adscore.signature.VerifierConstant.results;


class Signature4VerifierService {

  private static final HashMap<Integer, Field> fieldIds =
      new HashMap<Integer, Field>() {
        {
          put(0x00, new Field("requestTime", "ulong"));
          put(0x01, new Field("signatureTime", "ulong"));
          put(0x40, new Field(null, "ushort"));
          put(0x80, new Field("masterSignType", "uchar"));
          put(0x81, new Field("customerSignType", "uchar"));
          put(0xC0, new Field("masterToken", "string"));
          put(0xC1, new Field("customerToken", "string"));
          put(0xC2, new Field("masterTokenV6", "string"));
          put(0xC3, new Field("customerTokenV6", "string"));
        }
      };

  Signature4VerificationResult verifySignature(
      String signature,
      String userAgent,
      String signRole,
      String key,
      boolean isKeyBase64Encoded,
      Integer expiry,
      String[] ipAddresses) throws VerifyError, VersionError, ParseError {

    Signature4VerificationResult validationResult = new Signature4VerificationResult();

    Map<String, Object> data;
    try {
      data = parse4(signature);
    } catch (VersionError e ) {
      data = parse3(signature);
    }

    String signRoleToken = (String) data.get(signRole + "Token");

    if (signRoleToken == null || signRoleToken.length() == 0) {
      throw new VerifyError("sign role signature mismatch");
    }

    int signType = SignatureVerifierUtils.characterToInt(data.get(signRole + "SignType"));

    for (String ipAddress : ipAddresses) {
      String token;
      if (ipAddress == null || ipAddress.length() == 0) {
        continue;
      }
      if (IpV6Utils.validate(ipAddress)) {

        if (!data.containsKey(signRole + "TokenV6")) {
          continue;
        }
        token = (String) data.get(signRole + "TokenV6");
        ipAddress = IpV6Utils.abbreviate(ipAddress);
      } else {
        if (!data.containsKey(signRole + "Token")) {
          continue;
        }

        token = (String) data.get(signRole + "Token");
      }

      int signatureTime = SignatureVerifierUtils.characterToInt(data.get("signatureTime"));
      int requestTime = SignatureVerifierUtils.characterToInt(data.get("requestTime"));

      for (String result : results.keySet()) {
        boolean isValid = false;
        String signatureBase =
                getBase(result, requestTime, signatureTime, ipAddress, userAgent);

        switch (signType) {
          case 1: //HASH_SHA256
            boolean isHashedDataEqualToToken =
                SignatureVerifierUtils.encode(
                        isKeyBase64Encoded ? SignatureVerifierUtils.keyDecode(key) : key,
                        signatureBase).equals(token);

            if (isHashedDataEqualToToken) {
              if (isExpired(expiry, signatureTime, requestTime)) {
                validationResult.setExpired(true);
                return validationResult;
              }
              isValid = true;
              break;
            }
            break;
          case 2: //SIGN_SHA256
            if (verifyData(signatureBase, token, key, isKeyBase64Encoded,"SHA256withECDSA")){
              isValid = true;
              break;
            }
            break;
          default:
            throw new VerifyError("unrecognized signature");
        }
        if (isValid){
          validationResult.setScore(Integer.valueOf(result));
          validationResult.setVerdict(results.get(result));
          validationResult.setIpAddress(ipAddress);
          validationResult.setRequestTime(
                  Integer.parseInt(String.valueOf(data.get("requestTime"))));
          validationResult.setSignatureTime(
                  Integer.parseInt(String.valueOf(data.get("signatureTime"))));

          return validationResult;
        }
      }
    }
    throw new StructParseError("no verdict");
  }

  private boolean verifyData(String signatureBase, String token, String key, boolean isKeyBase64Encoded, String algorithm) throws VerifyError {
    AsymOpenSSL crypt = new AsymOpenSSL(algorithm);

    if (key.contains("BEGIN")){
      key = key.replace("-----BEGIN PUBLIC KEY-----", "")
              .replace("-----END PUBLIC KEY-----", "")
              .replaceAll("\\s", "");
    }

    byte[] keyBytes = isKeyBase64Encoded ? Base64.getMimeDecoder().decode(key) : key.getBytes();
    if(crypt.verify(signatureBase,token, keyBytes)){
      throw new VerifyError("Signature verification error");
    }

    return true;
  }

  /**
   * @param expiry how long request and signature are valid (in seconds)
   * @param signatureTime epoch time in seconds
   * @param requestTime epoch time in seconds
   * @return false if expiry is null. True if either signatureTime or requestTime expired, false
   *     otherwise.
   */
  boolean isExpired(Integer expiry, int signatureTime, int requestTime) {

    if (expiry == null) {
      // If expiry time not provided, neither signatureTime nor requestTime can be expired.
      return false;
    }

    long currentEpochInSeconds = new Date().getTime() / 1000;

    // Cast both times to long, because operating on int epoch seconds exceeds integer max value
    // while adding higher dates (around 2035)
    boolean isSignatureTimeExpired = (long) signatureTime + (long) expiry < currentEpochInSeconds;
    boolean isRequestTimeExpired = (long) requestTime + (long) expiry < currentEpochInSeconds;

    return isSignatureTimeExpired || isRequestTimeExpired;
  }

  String getBase(
      String verdict, int requestTime, int signatureTime, String ipAddress, String userAgent) {
    StringJoiner joiner = new StringJoiner("\n");

    return joiner
        .add(verdict)
        .add(String.valueOf(requestTime))
        .add(String.valueOf(signatureTime))
        .add(ipAddress)
        .add(userAgent)
        .toString();
  }

  private Map<String, Object> parse3(String signature)
          throws VersionError, SignatureParseError {
    ByteBuffer signBuffer = ByteBuffer.wrap(base64Decode(signature));

    if (!"".equals(signature)) {
      throw new SignatureParseError("invalid base64 payload");
    }

    Map<String, Object> unpackResult = PhpUnpack.unpack(
            "Cversion/NrequestTime/NsignatureTime/CmasterSignType/nmasterTokenLength", signBuffer);

    Integer version = (Integer) unpackResult.get("version");

    if (version != 3) {
      throw new VersionError("Invalid signature version");
    }

    Long timestamp = (Long) unpackResult.get("timestamp");
    if (timestamp > (new Date().getTime() / 1000)) {
      throw new SignatureParseError("invalid timestamp (future time)");
    }

    Integer masterTokenLength = (Integer) unpackResult.get("masterTokenLength");
    String masterToken = getBytesAndAdvancePosition(signBuffer, masterTokenLength);
    unpackResult.put("masterToken", masterToken);

    int s1, s2;

    if ((s1 = masterTokenLength) != (s2 = masterToken.length())) {
      throw new SignatureParseError(
          String.format("master token length mismatch (%s / %s)", s1, s2));
    }

    Map<String, Object> data2 = PhpUnpack.unpack("CcustomerSignType/ncustomerTokenLength", signBuffer);

    Integer customerTokenLength = (Integer) data2.get("customerTokenLength");
    String customerToken = getBytesAndAdvancePosition(signBuffer, customerTokenLength);
    data2.put("customerToken", customerToken);

    if ((s1 = customerTokenLength) != (s2 = customerToken.length())) {
      throw new SignatureParseError(
          String.format("customer token length mismatch (%s / %s)')", s1, s2));
    }

    unpackResult.putAll(data2);

    return unpackResult;
  }

  private Field fieldTypeDef(Integer fieldId, int i) {
    if (fieldIds.get(fieldId) != null) {
      return fieldIds.get(fieldId);
    }

    String resultType = fieldIds.get(fieldId & 0xC0).getType();

    String iStr = SignatureVerifierUtils.padStart(String.valueOf(i), 2, '0');
    String resultName = resultType + iStr;

    return new Field(resultName, resultType);
  }

  private Map<String, Object> parse4(String signature)
          throws VersionError, SignatureParseError {
    ByteBuffer signBB = ByteBuffer.wrap(base64Decode(signature));
    signature = new String(base64Decode(signature), StandardCharsets.ISO_8859_1);

    if (signature.length() == 0) {
      throw new SignatureParseError("invalid base64 payload");
    }

    Map<String, Object> data = PhpUnpack.unpack("Cversion/CfieldNum", signBB);

    int version = SignatureVerifierUtils.characterToInt(data.get("version"));
    if (version != 4) {
      throw new VersionError("Invalid signature version");
    }
    int fieldNum = SignatureVerifierUtils.characterToInt(data.get("fieldNum"));

    for (int i = 0; i < fieldNum; ++i) {
      Map<String, Object> header = PhpUnpack.unpack("CfieldId", signBB);
      signBB.position(signBB.position()-1);

      if (header.entrySet().size() == 0 || !header.containsKey("fieldId")) {
        throw new SignatureParseError("premature end of signature 0x01");
      }

      Field fieldTypeDef =
          fieldTypeDef(SignatureVerifierUtils.characterToInt(header.get("fieldId")), i);
      Map<String, Object> v = new HashMap<>();
      Map<String, Object> l;

      switch (fieldTypeDef.getType()) {
        case "uchar":
          v = PhpUnpack.unpack("Cx/Cv", signBB);
          if (v.containsKey("v")) {
            data.put(fieldTypeDef.getName(), v.get("v"));
          } else {
            throw new SignatureParseError("premature end of signature 0x02");
          }
          break;
        case "ushort":
          v = PhpUnpack.unpack("Cx/nv", signBB);
          if (v.containsKey("v")) {
            data.put(fieldTypeDef.getName(), v.get("v"));
          } else {
            throw new SignatureParseError("premature end of signature 0x03");
          }
          break;
        case "ulong":
          v = PhpUnpack.unpack("Cx/Nv", signBB);

          if (v.containsKey("v")) {
            data.put(fieldTypeDef.getName(), v.get("v"));
          } else {
            throw new SignatureParseError("premature end of signature 0x04");
          }
          break;
        case "string":
          l = PhpUnpack.unpack("Cx/nl", signBB);

          if (!l.containsKey("l")) {
            throw new SignatureParseError("premature end of signature 0x05");
          }
          if ((SignatureVerifierUtils.characterToInt(l.get("l")) & 0x8000) > 0) {
            int newl = SignatureVerifierUtils.characterToInt(l.get("l")) & 0xFF;
            l.put("l", newl);
          }

          int lLength = SignatureVerifierUtils.characterToInt(l.get("l"));
          String newV = getBytesAndAdvancePosition(signBB, lLength);
          v.put("v", newV);
          data.put(fieldTypeDef.getName(), newV);

          if (newV.getBytes(StandardCharsets.ISO_8859_1).length != lLength) {
            throw new SignatureParseError("premature end of signature 0x06");
          }
          break;
        default:
          throw new SignatureParseError("unsupported variable type");
      }
    }

    data.remove(String.valueOf(fieldNum));

    return data;
  }

  private String getBytesAndAdvancePosition(ByteBuffer buffer, int numBytes) {
    int currentPosition = buffer.position();
    int bytesToGet = Math.min(buffer.remaining(), numBytes);
    byte[] subArray = new byte[bytesToGet];
    buffer.get(subArray);
    buffer.position(currentPosition + bytesToGet);

    return new String(subArray, StandardCharsets.ISO_8859_1);
  }
}
