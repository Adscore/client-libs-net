using System;

namespace AdScore.Signature.Helpers
{
    internal static class ByteArrayHelper
    {
        public static bool Compare(ReadOnlySpan<byte> a1, ReadOnlySpan<byte> a2)
        {
            return a1.SequenceEqual(a2);
        }
    }
}
