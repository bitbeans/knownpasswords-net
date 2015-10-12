namespace knownpasswords.Models
{
    /// <summary>
    ///     Represents a libsodium key pair in hex format.
    /// </summary>
    public class AuthenticationPair
    {
        /// <summary>
        ///     The clients private key.
        /// </summary>
        public string PrivateKey { get; set; }

        /// <summary>
        ///     The clients public key.
        /// </summary>
        public string PublicKey { get; set; }
    }
}