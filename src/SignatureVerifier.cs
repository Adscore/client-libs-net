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

using AdScore.Signature.Exceptions;
using AdScore.Signature.Extensions;
using AdScore.Signature.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;

[assembly: InternalsVisibleTo("AdscoreClientNetLibs.Signature.Tests")]
namespace AdScore.Signature
{
    public class SignatureVerifier
    {
        private static readonly Dictionary<int, Field> _fieldIds = new Dictionary<int, Field>() {
          {0x00, new Field("requestTime", "ulong")},
          {0x01, new Field("signatureTime", "ulong")},
          {0x40, new Field(null, "ushort")},
          {0x80, new Field("masterSignType", "uchar")},
          {0x81, new Field("customerSignType", "uchar")},
          {0xC0, new Field("masterToken", "string")},
          {0xC1, new Field("customerToken", "string")},
          {0xC2, new Field("masterTokenV6", "string")},
          {0xC3, new Field("customerTokenV6", "string")}
        };

        private static readonly Dictionary<string, string> _results = new Dictionary<string, string>() {
          {"0", "ok"},
          {"3", "junk"},
          {"6", "proxy"},
          {"9", "bot"}
        };

        /// <summary>
        /// 
        /// </summary>
        /// <param name="signature">the string which we want to verify</param>
        /// <param name="userAgent">string with full description of user agent like 'Mozilla/5.0 (Linux; Android 9; SM-J530F)...'</param>
        /// <param name="signRole">string which specifies if we operate in customer or master role. For AdScore customers this should be always set to 'customer'</param>
        /// <param name="key">string containing related zone key</param>
        /// <param name="ipAddresses">array of strings containing ip4 or ip6 addresses against which we check signature</param>
        /// <returns></returns>
        public static SignatureVerificationResult Verify(string signature, string userAgent, string signRole, string key, params string[] ipAddresses)
        {
            return SignatureVerifier.Verify(signature, userAgent, signRole, key, true, null, ipAddresses);
        }

        /// <summary>
        /// 
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
                signature, userAgent, signRole, key, isKeyBase64Encoded, null, ipAddresses);
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

            SignatureVerificationResult validationResult = new SignatureVerificationResult();

            try
            {
                key = isKeyBase64Encoded ? KeyDecode(key) : key;

                Dictionary<string, Object> data;
                try
                {
                    data = Parse4(signature);
                }
                catch (BaseSignatureVerificationException exp)
                {
                    if (exp is SignatureRangeException)
                    {
                        data = Parse3(signature);
                    }
                    else
                    {
                        validationResult.Error = exp.Message;
                        return validationResult;
                    }
                }

                data.TryGetValue(signRole + "Token", out var signRoleTokenObj);
                string signRoleToken = (string)signRoleTokenObj;

                if (signRoleToken == null || signRoleToken.Length == 0)
                {

                    validationResult.Error = "sign role signature mismatch";
                    return validationResult;
                }

                int signType = GeneralUtils.CharacterToInt(data[signRole + "SignType"]);

                foreach (var ipAddress in ipAddresses)
                {
                    string currentIpAddress = ipAddress;
                    string token;
                    if (ipAddress == null || ipAddress.Length == 0)
                    {
                        continue;
                    }
                    if (IpV6Utils.Validate(ipAddress))
                    {

                        if (!data.ContainsKey(signRole + "TokenV6"))
                        {
                            continue;
                        }
                        token = (string)data[signRole + "TokenV6"];
                        currentIpAddress = IpV6Utils.Abbreviate(ipAddress);
                    }
                    else
                    {
                        if (!data.ContainsKey(signRole + "Token"))
                        {
                            continue;
                        }

                        token = (string)data[signRole + "Token"];
                    }

                    foreach (string result in _results.Keys)
                    {
                        switch (signType)
                        {
                            case 1:
                                string signatureBase =
                                    GetBase(
                                        result,
                                        GeneralUtils.CharacterToInt(data["requestTime"]),
                                        GeneralUtils.CharacterToInt(data["signatureTime"]),
                                        currentIpAddress,
                                        userAgent);

                                var inputbytes = Encoding.UTF8.GetBytes(HashData(signatureBase, key));
                                var test = Encoding.UTF8.GetBytes(token);

                                bool isHashedDataEqualToToken = ByteArrayHelper.Compare(HashData(signatureBase, key).ToIso88591EncodingByteArray(), token.ToIso88591EncodingByteArray());

                                if (isHashedDataEqualToToken)
                                {
                                    if (expiry != null && GeneralUtils.CharacterToInt(data["signatureTime"]) + expiry < GeneralUtils.UnixTimestamp / 1000)
                                    {
                                        validationResult.Expired = true;
                                        return validationResult;
                                    }

                                    validationResult.Score = int.Parse(result);
                                    validationResult.Verdict = _results[result.ToString()];
                                    validationResult.IpAddress = currentIpAddress;
                                    validationResult.RequestTime = int.Parse(data["requestTime"].ToString());
                                    validationResult.SignatureTime = int.Parse(data["signatureTime"].ToString());

                                    return validationResult;
                                }
                                break;
                            case 2:
                                validationResult.Error = "unsupported signature";
                                return validationResult;
                            default:
                                validationResult.Error = "unrecognized signature";
                                return validationResult;
                        }
                    }
                }

                validationResult.Error = "no verdict";
                return validationResult;

            }
            catch (Exception exp)
            {
                string base64Exception = "The input is not a valid Base-64 string";

                if (exp.Message.StartsWith(base64Exception))
                {
                    validationResult.Error = exp.Message.Replace(base64Exception, "Key is not a valid Base-64 string");
                    return validationResult;
                }
                else
                {
                    validationResult.Error = exp.Message;
                    return validationResult;
                }
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="key">in base64 format</param>
        /// <returns>decoded key</returns>
        internal static string KeyDecode(string key)
        {
            return Atob(key);
        }

        internal static string Atob(string str)
        {
            var isoBytes = Convert.FromBase64String(str);
            var utf8Bytes = Encoding.Convert(Encoding.GetEncoding("iso-8859-1"), Encoding.UTF8, isoBytes);
            return Encoding.UTF8.GetString(utf8Bytes, 0, utf8Bytes.Length);
        }

        internal static string PadStart(string inputstring, int length, char c)
        {
            if (inputstring.Length >= length)
            {
                return inputstring;
            }
            StringBuilder sb = new StringBuilder();
            while (sb.Length < length - inputstring.Length)
            {
                sb.Append(c);
            }
            sb.Append(inputstring);

            return sb.ToString();
        }

        internal static string GetBase(
            string verdict, int requestTime, int signatureTime, string ipAddress, string userAgent)
        {
            StringBuilder builder = new StringBuilder();

            return builder
                .Append(verdict)
                .Append("\n")
                .Append(requestTime.ToString())
                .Append("\n")
                .Append(signatureTime.ToString())
                .Append("\n")
                .Append(ipAddress)
                .Append("\n")
                .Append(userAgent)
                .ToString();
        }

        private static string FromBase64(string data)
        {
            int mod4 = data.Length % 4;
            if (mod4 > 0)
            {
                data += new string('=', 4 - mod4);
            }

            return Atob(data.Replace('_', '/').Replace('-', '+'));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="format"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        /// <exception cref="SignatureVerificationException"></exception>
        private static Dictionary<string, Object> Unpack(string format, string data)
        {
            int formatPointer = 0;
            int dataPointer = 0;
            Dictionary<string, Object> result = new Dictionary<string, Object>();
            int instruction;
            string quantifier;
            int quantifierInt;
            string label;
            string currentData;
            int i;
            int currentResult;

            while (formatPointer < format.Length)
            {
                instruction = GeneralUtils.CharAt(format, formatPointer);
                quantifier = "";
                formatPointer++;

                while ((formatPointer < format.Length)
                    && IsCharMatches(@"\A(?:[\\d\\*])\z", GeneralUtils.CharAt(format, formatPointer)))
                {
                    quantifier += GeneralUtils.CharAt(format, formatPointer);
                    formatPointer++;
                }
                if (string.IsNullOrEmpty(quantifier))
                {
                    quantifier = "1";
                }

                StringBuilder labelSb = new StringBuilder();
                while ((formatPointer < format.Length) && (format[formatPointer] != '/'))
                {
                    labelSb.Append(GeneralUtils.CharAt(format, formatPointer++));
                }
                label = labelSb.ToString();

                if (GeneralUtils.CharAt(format, formatPointer) == '/')
                {
                    formatPointer++;
                }

                switch (instruction)
                {
                    case 'c':
                    case 'C':
                        if ("*".Equals(quantifier))
                        {
                            quantifierInt = data.Length - dataPointer;
                        }
                        else
                        {
                            quantifierInt = int.Parse(quantifier);
                        }

                        currentData = GeneralUtils.Substr(data, dataPointer, quantifierInt);
                        dataPointer += quantifierInt;

                        for (i = 0; i < currentData.Length; i++)
                        {
                            currentResult = GeneralUtils.CharAt(currentData, i);

                            if ((instruction == 'c') && (currentResult >= 128))
                            {
                                currentResult -= 256;
                            }

                            string key = label + (quantifierInt > 1 ? (i + 1).ToString() : "");
                            result.Add(key, currentResult);
                        }
                        break;
                    case 'n':
                        if ("*".Equals(quantifier))
                        {
                            quantifierInt = (data.Length - dataPointer) / 2;
                        }
                        else
                        {
                            quantifierInt = int.Parse(quantifier);
                        }

                        currentData = GeneralUtils.Substr(data, dataPointer, quantifierInt * 2);
                        dataPointer += quantifierInt * 2;
                        for (i = 0; i < currentData.Length; i += 2)
                        {
                            currentResult =
                                (((GeneralUtils.CharAt(currentData, i) & 0xFF) << 8)
                                    + (GeneralUtils.CharAt(currentData, i + 1) & 0xFF));

                            string key = label + (quantifierInt > 1 ? ((i / 2) + 1).ToString() : "");
                            result.Add(key, currentResult);
                        }
                        break;
                    case 'N':
                        if ("*".Equals(quantifier))
                        {
                            quantifierInt = (data.Length - dataPointer) / 4;
                        }
                        else
                        {
                            quantifierInt = int.Parse(quantifier);
                        }

                        currentData = GeneralUtils.Substr(data, dataPointer, quantifierInt * 4);
                        dataPointer += quantifierInt * 4;
                        for (i = 0; i < currentData.Length; i += 4)
                        {
                            currentResult =
                                (((GeneralUtils.CharAt(currentData, i) & 0xFF) << 24)
                                    + ((GeneralUtils.CharAt(currentData, i + 1) & 0xFF) << 16)
                                    + ((GeneralUtils.CharAt(currentData, i + 2) & 0xFF) << 8)
                                    + ((GeneralUtils.CharAt(currentData, i + 3) & 0xFF)));

                            string key = label + (quantifierInt > 1 ? ((i / 4) + 1).ToString() : "");
                            result.Add(key, currentResult);
                        }
                        break;
                    default:
                        throw new SignatureVerificationException(
                            string.Format("Unknown format code: {0}", instruction.ToString()));
                }
            }

            return result;
        }

        private static bool IsCharMatches(string regex, int formatChar)
        {
            var matches = Regex.Matches(formatChar.ToString(), regex);
            return matches.Count > 0;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="signature"></param>
        /// <returns></returns>
        /// <exception cref="BaseSignatureVerificationException"></exception>
        private static Dictionary<string, Object> Parse3(string signature)
        {
            signature = FromBase64(signature);
            if (!"".Equals(signature))
            {
                throw new SignatureVerificationException("invalid base64 payload");
            }

            Dictionary<string, Object> data1 =
                Unpack(
                    "Cversion/NrequestTime/NsignatureTime/CmasterSignType/nmasterTokenLength", signature);

            int version = (int)data1["version"];

            if (version != 3)
            {
                throw new SignatureRangeException("unsupported version");
            }

            long timestamp = (long)data1["timestamp"];
            if (timestamp > (GeneralUtils.UnixTimestamp / 1000))
            {
                throw new SignatureVerificationException("invalid timestamp (future time)");
            }

            int masterTokenLength = (int)data1["masterTokenLength"];
            string masterToken = GeneralUtils.Substr(signature, 12, masterTokenLength + 12);
            data1.Add("masterToken", masterToken);

            int s1, s2;

            if ((s1 = masterTokenLength) != (s2 = masterToken.Length))
            {
                throw new SignatureVerificationException(
                    string.Format("master token length mismatch ({0} / {1})", s1, s2));
            }

            signature = GeneralUtils.Substr(signature, masterTokenLength + 12);

            Dictionary<string, Object> data2 = Unpack("CcustomerSignType/ncustomerTokenLength", signature);

            int customerTokenLength = (int)data2["customerTokenLength"];
            string customerToken = GeneralUtils.Substr(signature, 3, customerTokenLength + 3);
            data2.Add("customerToken", customerToken);

            if ((s1 = customerTokenLength) != (s2 = customerToken.Length))
            {
                throw new SignatureVerificationException(
                    string.Format("customer token length mismatch ({0} / {1})')", s1, s2));
            }

            return data1.Union(data2).ToDictionary(k => k.Key, v => v.Value);
        }

        private static Field FieldTypeDef(int fieldId, int i)
        {
            if (_fieldIds.TryGetValue(fieldId, out var value))
            {
                return value;
            }

            string resultType = _fieldIds[fieldId & 0xC0].Type;

            string iStr = PadStart(i.ToString(), 2, '0');
            string resultName = resultType + iStr;

            return new Field(resultName, resultType);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="signature"></param>
        /// <returns></returns>
        /// <exception cref="BaseSignatureVerificationException"></exception>
        private static Dictionary<string, Object> Parse4(string signature)

        {
            signature = FromBase64(signature);

            if (signature.Length == 0)
            {
                throw new SignatureVerificationException("invalid base64 payload");
            }

            Dictionary<string, Object> data = Unpack("Cversion/CfieldNum", signature);

            int version = GeneralUtils.CharacterToInt(data["version"]);
            if (version != 4)
            {
                throw new SignatureRangeException("unsupported version");
            }
            signature = GeneralUtils.Substr(signature, 2);

            int fieldNum = GeneralUtils.CharacterToInt(data["fieldNum"]);

            for (int i = 0; i < fieldNum; ++i)
            {
                Dictionary<string, Object> header = Unpack("CfieldId", signature);

                if (header.Count == 0 || !header.ContainsKey("fieldId")) // header.entrySet().size() ???
                {
                    throw new SignatureVerificationException("premature end of signature 0x01");
                }

                Field fieldTypeDef = SignatureVerifier.FieldTypeDef(GeneralUtils.CharacterToInt(header["fieldId"]), i);
                Dictionary<string, Object> v = new Dictionary<string, Object>();
                Dictionary<string, Object> l;

                switch (fieldTypeDef.Type)
                {
                    case "uchar":
                        v = Unpack("Cx/Cv", signature);
                        if (v.ContainsKey("v"))
                        {
                            data.Add(fieldTypeDef.Name, v["v"]);
                        }
                        else
                        {
                            throw new SignatureVerificationException("premature end of signature 0x02");
                        }
                        signature = GeneralUtils.Substr(signature, 2);
                        break;
                    case "ushort":
                        v = Unpack("Cx/nv", signature);
                        if (v.ContainsKey("v"))
                        {
                            data.Add(fieldTypeDef.Name, v["v"]);
                        }
                        else
                        {
                            throw new Exception("premature end of signature 0x03");
                        }
                        signature = GeneralUtils.Substr(signature, 3);
                        break;
                    case "ulong":
                        v = Unpack("Cx/Nv", signature);
                        if (v.ContainsKey("v"))
                        {
                            data.Add(fieldTypeDef.Name, v["v"]);
                        }
                        else
                        {
                            throw new Exception("premature end of signature 0x04");
                        }
                        signature = GeneralUtils.Substr(signature, 5);
                        break;
                    case "string":
                        l = Unpack("Cx/nl", signature);
                        if (!l.ContainsKey("l"))
                        {
                            throw new Exception("premature end of signature 0x05");
                        }
                        if ((GeneralUtils.CharacterToInt(l["l"]) & 0x8000) > 0)
                        {
                            int newl = GeneralUtils.CharacterToInt(l["l"]) & 0xFF;
                            l.Add("l", newl);
                        }

                        string newV = GeneralUtils.Substr(signature, 3, GeneralUtils.CharacterToInt(l["l"]));
                        v.Add("v", newV);
                        data.Add(fieldTypeDef.Name, newV);

                        if (((string)v["v"]).Length != GeneralUtils.CharacterToInt(l["l"]))
                        {
                            throw new SignatureVerificationException("premature end of signature 0x06");
                        }

                        signature = GeneralUtils.Substr(signature, 3 + GeneralUtils.CharacterToInt(l["l"]));

                        break;
                    default:
                        throw new SignatureVerificationException("unsupported variable type");
                }
            }

            data.Remove(fieldNum.ToString());

            return data;
        }

        private static string HashData(string data, string key)
        {
            return GeneralUtils.Encode(key, data);
        }
    }
}
