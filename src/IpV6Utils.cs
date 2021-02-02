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
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace AdScore.Signature
{
    internal class IpV6Utils
    {

        internal static bool Validate(string ipAddress)
        {
            if (IPNetwork.TryParse(ipAddress, out var output))
            {
                return output.AddressFamily == AddressFamily.InterNetworkV6;
            }

            return false;
        }

        internal static string Abbreviate(string input)
        {
            if (!Validate(input))
            {
                throw new SignatureVerificationException(string.Format("Invalid address: {0}", input));
            }

            string suffix = "";

            if (input.Contains("/"))
            {
                suffix = input.Substring(input.IndexOf("/"));
                return IPNetwork.Parse(input).FirstUsable.ToString() + suffix;
            }

            var hasMoreThanOneZeroBlocks = input.Split(':').Count(f => f == "0000") > 1;

            var removedExtraZeros = input.Replace("0000", "*");

            if (!input.Contains("::"))
                removedExtraZeros = new Regex(":0+").Replace(removedExtraZeros, ":");

            if (hasMoreThanOneZeroBlocks)
                removedExtraZeros = new Regex("(:\\*)+").Replace(removedExtraZeros, "::", 1);

            var removedAdditionalColons = new Regex("::+").Replace(removedExtraZeros, "::");

            return removedAdditionalColons.Replace("*", "0") + suffix;
        }
    }
}