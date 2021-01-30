using System;

namespace AdScore.Signature.Exceptions
{
    public abstract class BaseSignatureVerificationException : Exception
    {
        public BaseSignatureVerificationException()
        {
        }

        public BaseSignatureVerificationException(string message)
            : base(message)
        {
        }

        public BaseSignatureVerificationException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}