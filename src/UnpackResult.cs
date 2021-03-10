using System;
using System.Collections.Generic;
using System.Text;

namespace AdScore.Signature
{
    internal class UnpackResult
    {
        public Dictionary<string, Object> Data { get; set; }
        public string Error { get; set; }

        public UnpackResult(Dictionary<string, Object> data)
        {
            Data = data;
        }

        public UnpackResult(string error)
        {
            Error = error;
        }
    }
}
