# java-common

[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)

This library provides various utilities for parsing [Adscore](https://adscore.com) signatures v4 and v5,
and virtually anything that might be useful for customers doing server-side
integration with the service.

## Compatibility

### Supported Signature v5 algorithms
1. `v5_0200H - OpenSSL CBC, HTTP query`
2. `v5_0200S - OpenSSL CBC, PHP serialize`
3. `v5_0201H - OpenSSL GCM, HTTP query`
4. `v5_0201S - OpenSSL GCM, PHP serialize`
5. `v5_0101H - sodium secretbox, HTTP query`
6. `v5_0101S - sodium secretbox, PHP serialize`
7. `v5_0200J - OpenSSL CBC, JSON`
8. `v5_0201J - OpenSSL GCM, JSON`
9. `v5_0101J - sodium secretbox, JSON`
10. `v5_0101M - sodium secretbox, msgpack`
11. `v5_0200M - OpenSSL CBC, msgpack`
12. `v5_0201M - OpenSSL GCM, msgpack`

### Not supported Signature v5 algorithms

1. `v5_0101I - sodium secretbox, igbinary`
2. `v5_0200I - OpenSSL CBC, igbinary`
3. `v5_0201I - OpenSSL GCM, igbinary`

## Install

JDK version >= 1.8 is required
<br><br>
<h4>Via Maven/Gradle central repository</h4>

The easiest way to utilize the library is to attach it as a Maven dependency:

```maven
<dependency>
    <groupId>com.adscore</groupId>
    <artifactId>java-common</artifactId>
    <version>1.0.0</version>
</dependency>
```

or as a Gradle dependency:

```gradle
implementation 'com.adscore:java-common:1.0.0'
```

You can follow library here: https://central.sonatype.com/artifact/com.adscore/java-common

<br><br>
<h5>Maven/Gradle static file</h5>

Download the latest release from <a href="https://github.com/Adscore/java-common/releases"> github releases<a/> and than add it as Maven depenendecy:

```maven
<dependency>
  <groupId>com.adscore</groupId>
   <artifactId>java-common</artifactId>
   <version>1.0.0</version>
   <scope>system</scope>
   <systemPath>${project.basedir}/libs/java-common-1.0.0.jar</systemPath>
</dependency>
```
or as a Gradle:

```gradle
compile files('libs/java-common-1.0.0.jar')
```

<br><br>
<h5>Build library manually</h5>

If you want you can also build the library yourself. in order to do that you need to ensure:
- JDK 1.8 or higher
- Gradle 6.2.0 or higher

if above is satisfied than simply run following:

```bash
user@PC:~/project-dir$ gradle build
```
or following if you do not have gradle installed globally:
```bash
user@PC:~/project-dir$ ./gradlew build
```

executing above should succesfully run unit tests and produce `java-common-x-x-x.jar` within `~/project-dir/build/libs` directory

If you wish you can also do:

```bash
user@PC:~/project-dir$ ./gradlew publishToMavenLocal
```

which should allow to reference library from your local repository.

## Usage

### V4 signature decryption

When zone's "Response signature algorithm" is set to "Hashing" or "Signing", it means that V4 signatures are in use. They provide basic means to check incoming traffic for being organic and valuable, but do not carry any additional information.

Following are few quick examples of how to use verifier, first import the entry point for library:

```java
import com.adscore.signature.Signature4Verifier;
[..]
```

than you have at least few options of how to verify signatures:

```java

    // Verify with base64 encoded key.
    // (No expiry parameter, the default expiry time for requestTime and signatureTime is 60s)
    Signature4VerificationResult result =
        Signature4Verifier.verify(
            "BAYAXlNKGQFeU0oggAGBAcAAIAUdn1gbCBmA-u-kF--oUSuFw4B93piWC1Dn-D_1_6gywQAgEXCqgk2zPD6hWI1Y2rlrtV-21eIYBsms0odUEXNbRbA",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36",
            "customer",
            "a2V5X25vbl9iYXNlNjRfZW5jb2RlZA==",
            "73.109.57.137");

    [..]

    // Verify with checking if expired and non base64 encoded key
    //
    // IF signatureTime + expiry > CurrentDateInSeconds
    // THEN result.getExpired() = true
    result =
        Signature4Verifier.verify(
            "BAYAXlNKGQFeU0oggAGBAcAAIAUdn1gbCBmA-u-kF--oUSuFw4B93piWC1Dn-D_1_6gywQAgEXCqgk2zPD6hWI1Y2rlrtV-21eIYBsms0odUEXNbRbA",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36",
            "customer",
            "key_non_base64_encoded",
            false, // notify that we use non encoded key
            60, // signature cant be older than 1 min 
            "73.109.57.137");
    [..]

    // Verify against number of ip4 and ip6 addresses
    //(No expiry parameter, the default expiry time for requestTime and signatureTime is 60s)
    result =
        Signature4Verifier.verify(
            "BAYAXlNKGQFeU0oggAGBAcAAIAUdn1gbCBmA-u-kF--oUSuFw4B93piWC1Dn-D_1_6gywQAgEXCqgk2zPD6hWI1Y2rlrtV-21eIYBsms0odUEXNbRbA",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36",
            "customer",
            "key_non_base64_encoded",
            false, // notify that we use non encoded key
                
             //Multiple ip addresses either from httpXForwardForIpAddresses and remoteIpAddresses header
            "73.109.57.137", "73.109.57.138", "73.109.57.139", "73.109.57.140", "0:0:0:0:0:ffff:4d73:55d3", "0:0:0:0:0:fffff:4d73:55d4", "0:0:0:0:0:fffff:4d73:55d5", "0:0:0:0:0:fffff:4d73:55d6");
    [..]

    // Verify against number of ip4 and ip6 addresses passed as an array
    String[] ipAddresses = {"73.109.57.137", "73.109.57.138", "73.109.57.139", "73.109.57.140", "0:0:0:0:0:ffff:4d73:55d3", "0:0:0:0:0:fffff:4d73:55d4", "0:0:0:0:0:fffff:4d73:55d5", "0:0:0:0:0:fffff:4d73:55d6"};
    result =
        Signature4Verifier.verify(
            "BAYAXlNKGQFeU0oggAGBAcAAIAUdn1gbCBmA-u-kF--oUSuFw4B93piWC1Dn-D_1_6gywQAgEXCqgk2zPD6hWI1Y2rlrtV-21eIYBsms0odUEXNbRbA",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36",
            "customer",
            "a2V5X25vbl9iYXNlNjRfZW5jb2RlZA==",
            360,  // signature cant be older than 5min
            ipAddresses);
    
    
    // result object will contain a non-null value in verdict field in case of success
    
    //  verifier throwing Exceptions, must be handled
    try {
        Signature4Verifier.verify(...);
        } catch (VersionError e) {
            /*  It means that the signature is not the V4 one, check your zone settings and ensure the signatures
                are coming from the chosen zone. */
        } catch (VerifyError e) {
            /*  Signature could not be verified - see error message for details. */
        } catch (ParseError e) {
            /*  It means that the signature metadata is malformed and cannot be parsed, or contains invalid data,
            check for corruption underway. */
        }
```

### V5 signature decryption

V5 is in fact an encrypted payload containing various metadata about the traffic. Its decryption does not rely on IP address 
nor User Agent string, so it is immune for environment changes usually preventing V4 to be even decoded. Judge result is also 
included in the payload, but client doing the integration can make its own decision basing on the metadata accompanying.

Zone has to be set explicitly to V5 signature, if you don't see the option, please contact support as we are rolling this 
mode on customer's demand. The format supports a wide variety of encryption and serialization methods, some of them are included 
in this repository, but it can be extended to fulfill specific needs.

It can be integrated in V4-compatible mode, not making use of any V5 features (see V4 verification):


```java
import com.adscore.signature.Signature5Verifier;


    //  verifier throwing Exceptions, must be handled
    try {
        Signature5VerificationResult result = Signature5Verifier.verify(
            "BQO7AAAAAAAB8RABAQX93o4s4rKP_WfrdzFP6ATAWgpXwS8Y7oECAcpVJXb-rGN2aH0KbFw5zvhEpoyEml6vRM7ePFigDUhDProdHA8uw1L62k57fX8t_j0UCEI6_oKHTvfU_fbfg2CXf0v64oRHxaKkcD3BqjQoL3ow89dAWX4xOsWHyO77xvxeh78yE7GTKVm8NDNQNkWbaLvv__y8vW2PHamWkqJypw9q4KYZ00YuIkn5DW5SmW-m1InOOyKySX64QKawwfsNqDE-vZBzFhQXLNGRpOsu_NWadjKE97Lm_1BLJ0QXscJmI0N77TyrpEjclI6b4yLiG0W_dkOSrStk3WPzbUv_dbY2UDAOoZaFr5PsXGPSEprVk1FNRmSaxxnGqYm8hD9y3c-VBqnDGPZIGpP-JXLrJv1q-s-XJkXXDIJyz89rDnRf10gn0iEC-wsocx5QBQunD1PNnkB8_r5xVXxKG2kgxeApVH7Bdbs9zf35enjD8VP8tA8-kiDR96jhcY0eJzSqXrMsRfpVqyPsJeGcex2DXNALWo8f07ikfH4fZxiQ9dzUTsY9zG0fH7SiRl1QexsKM6ICeKVSbublStF-XnbqHAc7BeShJGBT1z5qF71i-vlut4xY7xNrgpiWX57ER8d3IPqJEqrktyAslNz-LKKLF2N5z03DZzpcqmv6E6e5PeI-eURYK871Xoc1vO03BUPjcyDH3Wge2qDg1u_38tP3p2V8deLYofk1hsfEyk6lLoCNd-293jOFqZ3quifwujueEmQ4NZwht9dtk5Ee-osYezvKT9UZyTjVQrGO6WWklhLTfi8a-ApL8M3_7fFX0MNL0JqQTrKtFJnrWpdH2eXOtAPBbmIfPGNXbei9R_kOY_v3FmHLVomRCCAbftVlwr8cxpdVn3CPu5lls9yR15_XpCFm8g4QZFQPM4sM4UCPlXQNiGo4M0DAFMIPFBsPYam-TAPTqKmPpCWDR9M-dHFMF5MdBkOmtAibElnRXuZxqBJO2nl8QO3zGI9TFqS7v_0d2r1ADCAjd9hWYJXcTkl1dWbo4Q-IFxKhof1d3TjjVf3wTyVzsiwbEJUV7FXg31qAyAZzSn6EqWhGAd6ocdQvsXS6KH6Q5FsTM6S5IJ4o4q9x7YN58css97WbFw5RffPNHNggU97sEqG4ZcPEwMo8yXNK6V03DJFgLBC2F7C16vzZNualajF92_wsJ5XgjzU7say5ucmDRtQA5IEisPz8jl9vuLL8quS-I-zsJA-MJh6QsowPoegk8Ur76kn0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "dj0lTcsmjDnDYPSL2+DQPN7QwirCQOlqnPhiXwusEM0=",
            Arrays.asList("176.103.168.60"));
        } catch (VersionError e) {
            /*  It means that the signature is not the V4 one, check your zone settings and ensure the signatures
                are coming from the chosen zone. */
            } catch (VerifyError e) {
            /*  Signature could not be verified - see error message for details. */
            } catch (ParseError e) {
            /*  It means that the signature metadata is malformed and cannot be parsed, or contains invalid data,
            check for corruption underway. */
            }
);
```

The result field score only after a successful verify() call. This is expected behavior, to preserve compliance with V4 behavior - the result is only valid when it's proven belonging to a visitor, in other case will be thrown exception. For custom integrations not relying on built-in verification routines (usually more tolerant), the result is present also in result field, but it's then the integrator's reponsibility to ensure whether it's trusted or not. When desired validation is more strict than the built-in one, the verify() can be called first, and after that any additional verification may take place. 

Note: V4 signature parser also holds the payload, but it does not contain any useful informations, only timestamps and signed strings; especially - it does not contain any Judge result value, it is derived from the signature via several hashing/verification approaches.

## Integration

Any questions you have with custom integration, please contact our support@adscore.com. Please remember that we do
require adequate technical knowledge in order to be able to help with the integration; there are other integration
methods which do not require any, or require very little programming.