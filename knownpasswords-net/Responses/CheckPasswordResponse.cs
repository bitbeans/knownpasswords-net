using System;

namespace knownpasswords.Responses
{
    [Serializable]
    public class CheckPasswordResponse
    {
        public bool FoundPassword { get; set; }
        public Data Data { get; set; }
    }

    [Serializable]
    public class Data
    {
        public string Cleartext { get; set; }
        public string Sha512 { get; set; }
        public string Blake2b { get; set; }
        public double ShannonEntropy { get; set; }
    }
}
