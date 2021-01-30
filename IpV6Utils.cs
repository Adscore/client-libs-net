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