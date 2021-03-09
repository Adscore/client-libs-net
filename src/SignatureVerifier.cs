#region License
/*
 * Copyright (c) 2021 AdScore Technologies DMCC [AE]
 *
 * Licensed under MIT License;
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#endregion

using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("AdscoreClientNetLibs.Signature.Tests")]
namespace AdScore.Signature
{
    public class SignatureVerifier
    {
        public static int DEFAULT_EXPIRY_TIME_SEC = 60;

        /// <summary>
        /// Default request and signature expiration is set to 60s
        /// </summary>
        /// <param name="signature">the string which we want to verify</param>
        /// <param name="userAgent">string with full description of user agent like 'Mozilla/5.0 (Linux; Android 9; SM-J530F)...'</param>
        /// <param name="signRole">string which specifies if we operate in customer or master role. For AdScore customers this should be always set to 'customer'</param>
        /// <param name="key">string containing related zone key</param>
        /// <param name="ipAddresses">array of strings containing ip4 or ip6 addresses against which we check signature</param>
        /// <returns></returns>
        public static SignatureVerificationResult Verify(string signature, string userAgent, string signRole, string key, params string[] ipAddresses)
        {
            return SignatureVerifier.Verify(signature, userAgent, signRole, key, true, DEFAULT_EXPIRY_TIME_SEC, ipAddresses);
        }

        /// <summary>
        /// Default request and signature expiration is set to 60s
        /// </summary>
        /// <param name="signature">the string which we want to verify</param>
        /// <param name="userAgent">string with full description of user agent like 'Mozilla/5.0 (Linux; Android 9; SM-J530F)...'</param>
        /// <param name="signRole">string which specifies if we operate in customer or master role. For AdScore customers this should be always set to 'customer'</param>
        /// <param name="key">string containing related zone key</param>
        /// <param name="expiry">Unix timestamp which is time in seconds. IF signatureTime + expiry > CurrentDateInSecondsTHEN result is expired</param>
        /// <param name="ipAddresses">array of strings containing ip4 or ip6 addresses against which we check signature</param>
        /// <returns></returns>
        public static SignatureVerificationResult Verify(
            string signature,
            string userAgent,
            string signRole,
            string key,
            int expiry,
            params string[] ipAddresses)
        {

            return SignatureVerifier.Verify(signature, userAgent, signRole, key, true, expiry, ipAddresses);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="signature">the string which we want to verify</param>
        /// <param name="userAgent">string with full description of user agent like 'Mozilla/5.0 (Linux; Android 9; SM-J530F)...'</param>
        /// <param name="signRole">string which specifies if we operate in customer or master role. For AdScore customers this should be always set to 'customer'</param>
        /// <param name="key">string containing related zone key</param>
        /// <param name="isKeyBase64Encoded">defining if passed key is base64 encoded or not</param>
        /// <param name="ipAddresses">array of strings containing ip4 or ip6 addresses against which we check signature</param>
        /// <returns></returns>
        public static SignatureVerificationResult Verify(
            string signature,
            string userAgent,
            string signRole,
            string key,
            bool isKeyBase64Encoded,
            params string[] ipAddresses)
        {

            return SignatureVerifier.Verify(
                signature, userAgent, signRole, key, isKeyBase64Encoded, DEFAULT_EXPIRY_TIME_SEC, ipAddresses);
        }

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
            bool isKeyBase64Encoded,
            int? expiry,
            params string[] ipAddresses)
        {
            return new SignatureVerifierService().VerifySignature(
                signature, userAgent, signRole, key, isKeyBase64Encoded, expiry, ipAddresses
            );
        }
    }
}
