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
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

[assembly: InternalsVisibleTo("AdscoreClientNetLibs.Signature.Tests")]
namespace AdScore.Signature
{
    internal class SignatureVerifierUtils
    {
        internal static Int64 UnixTimestamp => Convert.ToInt64((DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalMilliseconds);

        internal static string Substr(string str, int startIdx, int length)
        {
            if (startIdx > str.Length)
            {
                return "";
            }

            length = length.Clamp(0, str.Length - startIdx);

            return str.Substring(startIdx, length);
        }

        internal static string Substr(string str, int length)
        {
            return SignatureVerifierUtils.Substr(str, length, str.Length);
        }

        internal static char CharAt(string str, int idx)
        {
            if ((idx < 0) || (idx >= str.Length))
            {
                return (char)0;
            }

            return str[idx];
        }

        internal static int CharacterToInt(Object obj)
        {
            return ((int)(obj));
        }

        internal static string Encode(string key, string data)
        {
            Encoding encoding = Encoding.GetEncoding("ISO-8859-1");

            Byte[] textBytes = encoding.GetBytes(data);
            Byte[] keyBytes = encoding.GetBytes(key);

            Byte[] hashBytes;

            using (HMACSHA256 hash = new HMACSHA256(keyBytes))
                hashBytes = hash.ComputeHash(textBytes);

            return encoding.GetString(hashBytes);
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

        internal static string FromBase64(string data)
        {
            if (string.IsNullOrWhiteSpace(data))
            {
                throw new SignatureVerificationException("empty key or signature");
            }

            int mod4 = data.Length % 4;
            if (mod4 > 0)
            {
                data += new string('=', 4 - mod4);
            }

            return Atob(data.Replace('_', '/').Replace('-', '+'));
        }

        internal static bool IsCharMatches(string regex, int formatChar)
        {
            var matches = Regex.Matches(formatChar.ToString(), regex);
            return matches.Count > 0;
        }

        internal static bool CompareBytes(string first, string second)
        {
            return ByteArrayHelper.Compare(first.ToIso88591EncodingByteArray(), second.ToIso88591EncodingByteArray());
        }
    }
}