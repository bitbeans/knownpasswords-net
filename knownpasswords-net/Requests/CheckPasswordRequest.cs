using System;

namespace knownpasswords.Requests
{
    [Serializable]
    public class CheckPasswordRequest
    {
        public string Cleartext { get; set; }
        public string Blake2b { get; set; }
        public string Sha512 { get; set; }
    }
}