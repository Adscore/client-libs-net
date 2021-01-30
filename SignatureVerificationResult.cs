namespace AdScore.Signature
{
    public class SignatureVerificationResult
    {
        public string IpAddress { get; set; }
        public string Verdict { get; set; }
        public int? Score { get; set; }
        public int? RequestTime { get; set; }
        public int? SignatureTime { get; set; }
        public bool? Expired { get; set; }
        public string Error { get; set; }
    }
}