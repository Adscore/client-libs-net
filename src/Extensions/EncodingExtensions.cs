using System;
using System.Collections.Generic;
using System.Text;

namespace AdScore.Signature.Extensions
{
    public static class EncodingExtensions
    {
        public static byte[] ToIso88591EncodingByteArray(this string input)
        {
            return Encoding.GetEncoding("ISO-8859-1").GetBytes(input);
        }

    }
}
