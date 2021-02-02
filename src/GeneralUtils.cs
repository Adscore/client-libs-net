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

using AdScore.Signature.Extensions;
using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

[assembly: InternalsVisibleTo("AdscoreClientNetLibs.Signature.Tests")]
namespace AdScore.Signature
{
    internal class GeneralUtils
    {
        public static Int64 UnixTimestamp => Convert.ToInt64((DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalMilliseconds);

        public static string Substr(string str, int startIdx, int length)
        {
            if (startIdx > str.Length)
            {
                return "";
            }

            length = length.Clamp(0, str.Length - startIdx);

            return str.Substring(startIdx, length);
        }

        public static string Substr(string str, int length)
        {
            return GeneralUtils.Substr(str, length, str.Length);
        }

        public static char CharAt(string str, int idx)
        {
            if ((idx < 0) || (idx >= str.Length))
            {
                return (char)0;
            }

            return str[idx];
        }

        public static int CharacterToInt(Object obj)
        {
            return ((int)(obj));
        }

        public static string Encode(string key, string data)
        {
            Encoding encoding = Encoding.GetEncoding("ISO-8859-1");

            Byte[] textBytes = encoding.GetBytes(data);
            Byte[] keyBytes = encoding.GetBytes(key);

            Byte[] hashBytes;

            using (HMACSHA256 hash = new HMACSHA256(keyBytes))
                hashBytes = hash.ComputeHash(textBytes);

            return encoding.GetString(hashBytes);
        }
    }
}