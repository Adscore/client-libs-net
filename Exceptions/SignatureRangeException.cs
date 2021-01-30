using System;

namespace AdScore.Signature.Exceptions
{
    public class SignatureRangeException : BaseSignatureVerificationException
    {
        public SignatureRangeException()
        {
        }

        public SignatureRangeException(string message)
            : base(message)
        {
        }

        public SignatureRangeException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}