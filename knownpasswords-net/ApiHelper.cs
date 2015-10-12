using System.Text;
using knownpasswords.Models;
using Sodium;

namespace knownpasswords
{
    /// <summary>
    ///     Some helper methods.
    /// </summary>
    public static class ApiHelper
    {
        /// <summary>
        ///     Helper method to generate a new API key pair.
        /// </summary>
        /// <returns>An new AuthenticationPair.</returns>
        public static AuthenticationPair GenerateApiKeyPair()
        {
            var keyPair = PublicKeyAuth.GenerateKeyPair();
            return new AuthenticationPair
            {
                PublicKey = Utilities.BinaryToHex(keyPair.PublicKey),
                PrivateKey = Utilities.BinaryToHex(keyPair.PrivateKey)
            };
        }

        /// <summary>
        ///     Convert a cleartext password to a Sha512 hex string.
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        public static string ConvertPasswordToSha512(string password)
        {
            return ConvertPasswordToSha512(Encoding.UTF8.GetBytes(password));
        }

        /// <summary>
        ///     Convert a cleartext password to a Sha512 hex string.
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        public static string ConvertPasswordToSha512(byte[] password)
        {
            return Utilities.BinaryToHex(CryptoHash.Sha512(password));
        }

        /// <summary>
        ///     Convert a cleartext password to a Blake2b hex string.
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        public static string ConvertPasswordToBlake2b(string password)
        {
            return ConvertPasswordToBlake2b(Encoding.UTF8.GetBytes(password));
        }

        /// <summary>
        ///     Convert a cleartext password to a Blake2b hex string.
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        public static string ConvertPasswordToBlake2b(byte[] password)
        {
            return Utilities.BinaryToHex(GenericHash.Hash(password, null, 64));
        }
    }
}