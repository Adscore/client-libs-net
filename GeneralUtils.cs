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