# What is it?

Various .NET Client libraries for utilization of APIs in [AdScore.com](https://adscore.com)

##### Latest version: 1.0.0 - currently available features:
1. SignatureVerifier

##### other languages:
 * PHP: https://github.com/Adscore/client-libs-php
 * JS: https://github.com/variably/adscore-node
 * Java: https://github.com/Adscore/client-libs-java

### Installation

```
Install-Package AdScore.Signature -Version 1.0.0
```

Or by downloading .nuget file need from releases and provided from local "Packages Folder"

https://docs.microsoft.com/pl-pl/nuget/consume-packages/install-use-packages-visual-studio#package-sources

https://docs.microsoft.com/pl-pl/nuget/reference/nuget-config-file

### Compatibility

|AdScore SignatureVerifier Version                 |.NET Standard|
|---------------------------------------------------|------|
|[1.0.0](https://github.com/Adscore/client-libs-net)|>= 1.6|

https://docs.microsoft.com/pl-pl/dotnet/standard/net-standard


## Features documentation

### 1. SignatureVerifier

The definition of verify function looks as follows:

```csharp
/// <summary>
/// 
/// </summary>
/// <param name="signature">the string which we want to verify</param>
/// <param name="userAgent">string with full description of user agent like 'Mozilla/5.0 (Linux; Android 9; SM-J530F)...'</param>
/// <param name="signRole">string which specifies if we operate in customer or master role. For AdScore customers this should be always set to 'customer'</param>
/// <param name="key">string containing related zone key</param>
/// <param name="isKeyBase64Encoded">defining if passed key is base64 encoded or not</param>
/// <param name="expiry">Unix timestamp which is time in seconds. IF signatureTime + expiry > CurrentDateInSeconds THEN result is expired</param>
/// <param name="ipAddresses">array of strings containing ip4 or ip6 addresses against which we check signature</param>
/// <returns></returns>
public static SignatureVerificationResult Verify(
    string signature,
    string userAgent,
    string signRole,
    string key,
    [bool isKeyBase64Encoded,] // optional due existence of overloaded function
    [int? expiry,] // optional due existence of overloaded function
    params string[] ipAddresses)
{
```

Following are few quick examples of how to use verifier, first import the entry point for library:

```csharp
using AdScore.Signature;
[..]
```

then you have at least few options of how to verify signatures:

```csharp

    // Verify with base64 encoded key and without expiry checking
    SignatureVerificationResult result =
        SignatureVerifier.Verify(
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
        SignatureVerifier.Verify(
            "BAYAXlNKGQFeU0oggAGBAcAAIAUdn1gbCBmA-u-kF--oUSuFw4B93piWC1Dn-D_1_6gywQAgEXCqgk2zPD6hWI1Y2rlrtV-21eIYBsms0odUEXNbRbA",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36",
            "customer",
            "key_non_base64_encoded",
            false, // notify that we use non encoded key
            60, // signature cant be older than 1 min
            "73.109.57.137");
    [..]

    // Verify against number of ip4 and ip6 addresses
    result =
        SignatureVerifier.Verify(
            "BAYAXlNKGQFeU0oggAGBAcAAIAUdn1gbCBmA-u-kF--oUSuFw4B93piWC1Dn-D_1_6gywQAgEXCqgk2zPD6hWI1Y2rlrtV-21eIYBsms0odUEXNbRbA",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36",
            "customer",
            "key_non_base64_encoded",
            false, // notify that we use non encoded key
            "73.109.57.137", "73.109.57.138", "73.109.57.139", "73.109.57.140", "0:0:0:0:0:ffff:4d73:55d3", "0:0:0:0:0:fffff:4d73:55d4", "0:0:0:0:0:fffff:4d73:55d5", "0:0:0:0:0:fffff:4d73:55d6");
    [..]

    // Verify against number of ip4 and ip6 addresses passed as an array
    String[] ipAddresses = {"73.109.57.137", "73.109.57.138", "73.109.57.139", "73.109.57.140", "0:0:0:0:0:ffff:4d73:55d3", "0:0:0:0:0:fffff:4d73:55d4", "0:0:0:0:0:fffff:4d73:55d5", "0:0:0:0:0:fffff:4d73:55d6"};
    result =
        SignatureVerifier.Verify(
            "BAYAXlNKGQFeU0oggAGBAcAAIAUdn1gbCBmA-u-kF--oUSuFw4B93piWC1Dn-D_1_6gywQAgEXCqgk2zPD6hWI1Y2rlrtV-21eIYBsms0odUEXNbRbA",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36",
            "customer",
            "a2V5X25vbl9iYXNlNjRfZW5jb2RlZA==",
            360,  // signature cant be older than 5min
            ipAddresses);
    
    
    // result object will contain a non-null value in verdict field in case of success
    // or a non-null value in error field in cases of failure
    
    if (result.Error != null) {
      // Failed to verify signature, handle error i.e.
      Logger.LogWarning("Failed to verify signature: " + result.Error);
    } else {
      Logger.LogInfo("Signature verification with verdict: " + result.Verdict + " for ip " + result.IpAddress);
    }
);
```
