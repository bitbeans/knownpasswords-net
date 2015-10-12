using System;

namespace knownpasswords.Responses
{
    [Serializable]
    public class EncryptedResponse
    {
        public string Ciphertext { get; set; }
        public string Nonce { get; set; }
        public string PublicKey { get; set; }
    }
}