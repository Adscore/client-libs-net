using System;

namespace AdScore.Signature.Exceptions
{
    public class SignatureVerificationException : BaseSignatureVerificationException
    {
        public SignatureVerificationException()
        {
        }

        public SignatureVerificationException(string message)
            : base(message)
        {
        }

        public SignatureVerificationException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}