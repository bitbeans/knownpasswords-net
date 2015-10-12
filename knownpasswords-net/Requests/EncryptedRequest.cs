using System;

namespace knownpasswords.Requests
{
    [Serializable]
    public class EncryptedRequest
    {
        public string Ciphertext { get; set; }
        public string Nonce { get; set; }
        public string PublicKey { get; set; }
    }
}