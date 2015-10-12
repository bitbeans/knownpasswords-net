using System;
using System.Linq;
using System.Net;
using System.Text;
using knownpasswords.Models;
using knownpasswords.Requests;
using knownpasswords.Responses;
using RestSharp;
using Sodium;

namespace knownpasswords
{
    /// <summary>
    ///     Class to communicate with the knownpasswords.org API.
    /// </summary>
    public class KnownPasswords
    {
        /// <summary>
        ///     The knownpasswords.org server signature public key (don`t change).
        /// </summary>
        private const string ServerSignaturePublicKeyHex = "e1426419742ee9f34831d3deaead88a511dc6fb635e3187427012457031e538a";
        /// <summary>
        ///     The knownpasswords.org server encryption public key (don`t change).
        /// </summary>
        private const string ServerEncryptionPublicKeyHex =
            "8609896949b031fb3109e6ed5564801ab6a839c88cc8b159c4d4771513b4564e";

        /// <summary>
        ///     The knownpasswords.org API url.
        /// </summary>
        private const string ServerApiUrl = "https://knownpasswords.org";

        private readonly RestClient _restClient;

        /// <summary>
        ///     Constructor to prepare the communication.
        /// </summary>
        /// <param name="clientPrivateKey">The clients 32 byte private key (hex format)</param>
        /// <exception cref="NotSupportedException"></exception>
        public KnownPasswords(string clientPrivateKey)
        {
            var curve25519SecretKey =
                PublicKeyAuth.ConvertEd25519SecretKeyToCurve25519SecretKey(Utilities.HexToBinary(clientPrivateKey));
            SignaurKeyPair =
                new KeyPair(
                    PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(Utilities.HexToBinary(clientPrivateKey)),
                    Utilities.HexToBinary(clientPrivateKey));
            EncryptionKeyPair = PublicKeyBox.GenerateKeyPair(curve25519SecretKey);

            // the API only accepts TLS 1.2 connections
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            _restClient = new RestClient(ServerApiUrl);
        }

        /// <summary>
        ///     The signature key pair.
        /// </summary>
        private KeyPair SignaurKeyPair { get; }

        /// <summary>
        ///     The encryption key pair.
        /// </summary>
        private KeyPair EncryptionKeyPair { get; }


        /// <summary>
        ///     Method to check a password.
        /// </summary>
        /// <param name="password"></param>
        /// <param name="passwordFormatType"></param>
        /// <returns></returns>
        public CheckPasswordResponse CheckPassword(byte[] password,
            PasswordFormatType passwordFormatType = PasswordFormatType.Blake2b)
        {
            var request = new RestRequest("/CheckPassword/", Method.POST) { RequestFormat = DataFormat.Json };
            var passwordRequest = new CheckPasswordRequest();
            switch (passwordFormatType)
            {
                case PasswordFormatType.Cleartext:
                    passwordRequest = (new CheckPasswordRequest {Cleartext = Encoding.UTF8.GetString(password)});
                    break;
                case PasswordFormatType.Blake2b:
                    passwordRequest = (new CheckPasswordRequest { Blake2b = Encoding.UTF8.GetString(password) });
                    break;
                case PasswordFormatType.Sha512:
                    passwordRequest = (new CheckPasswordRequest { Sha512 = Encoding.UTF8.GetString(password) });
                    break;
            }
            // encrypt the request
            request.AddBody(EncryptCheckPasswordRequest(passwordRequest));

            // sign the request
            request = AddHeaders(request);

            try
            {
                var response = _restClient.Execute<EncryptedResponse>(request);
                if (response.StatusCode == HttpStatusCode.OK)
                {
                    var responseNonce = response.Headers.SingleOrDefault(h => h.Name.Equals("X-Nonce"));
                    var responsePublic = response.Headers.SingleOrDefault(h => h.Name.Equals("X-Public"));
                    var responseSignature = response.Headers.SingleOrDefault(h => h.Name.Equals("X-Signature"));
                    if ((responseNonce != null) && (responsePublic != null) && (responseSignature != null))
                    {
                        // validate the response signature
                        if (PublicKeyAuth.VerifyDetached(Utilities.HexToBinary(responseSignature.Value.ToString()), GenericHash.Hash(Utilities.HexToBinary(responseNonce.Value.ToString()), null, 64), Utilities.HexToBinary(ServerSignaturePublicKeyHex)))
                        {
                            return DecryptCheckPasswordResponse(response.Data);
                        }
                    }
                }
            }
            catch (Exception)
            {
            }
            return new CheckPasswordResponse();
        }


        /// <summary>
        ///     Method to check a password.
        /// </summary>
        /// <param name="password"></param>
        /// <param name="passwordFormatType"></param>
        /// <returns></returns>
        public CheckPasswordResponse CheckPassword(string password, PasswordFormatType passwordFormatType = PasswordFormatType.Blake2b)
        {
            return CheckPassword(Encoding.UTF8.GetBytes(password), passwordFormatType);
        }

        public ApiInformationResponse ApiInformation()
        {
            var request = new RestRequest("/Version/", Method.GET) { RequestFormat = DataFormat.Json };
            try
            {
                var response = _restClient.Execute<ApiInformationResponse>(request);
                if (response.StatusCode == HttpStatusCode.OK)
                {
                    var responseNonce = response.Headers.SingleOrDefault(h => h.Name.Equals("X-Nonce"));
                    var responsePublic = response.Headers.SingleOrDefault(h => h.Name.Equals("X-Public"));
                    var responseSignature = response.Headers.SingleOrDefault(h => h.Name.Equals("X-Signature"));
                    if ((responseNonce != null) && (responsePublic != null) && (responseSignature != null))
                    {
                        // validate the response signature
                        if (PublicKeyAuth.VerifyDetached(Utilities.HexToBinary(responseSignature.Value.ToString()), GenericHash.Hash(Utilities.HexToBinary(responseNonce.Value.ToString()), null, 64), Utilities.HexToBinary(ServerSignaturePublicKeyHex)))
                        {
                            return response.Data;
                        }
                    }
                }
            }
            catch (Exception)
            {
            }
            return new ApiInformationResponse();
        }

        private static EncryptedRequest EncryptCheckPasswordRequest(CheckPasswordRequest checkPasswordRequest)
        {
            var encryptedRequest = new EncryptedRequest();
            try
            {
                var clearText = SimpleJson.SerializeObject(checkPasswordRequest);
                var nonce = PublicKeyBox.GenerateNonce();
                var ephemeralKeyPair = PublicKeyBox.GenerateKeyPair();
                var cipher = PublicKeyBox.Create(Encoding.UTF8.GetBytes(clearText), nonce, ephemeralKeyPair.PrivateKey,
                    Utilities.HexToBinary(ServerEncryptionPublicKeyHex));
                encryptedRequest.PublicKey = Utilities.BinaryToHex(ephemeralKeyPair.PublicKey);
                encryptedRequest.Ciphertext = Utilities.BinaryToHex(cipher);
                encryptedRequest.Nonce = Utilities.BinaryToHex(nonce);
            }
            catch (Exception)
            {
            }
            return encryptedRequest;
        }

        private CheckPasswordResponse DecryptCheckPasswordResponse(EncryptedResponse encryptedResponse)
        {
            var checkPasswordResponse = new CheckPasswordResponse();
            try
            {
                var clearText = Encoding.UTF8.GetString(PublicKeyBox.Open(Utilities.HexToBinary(encryptedResponse.Ciphertext), Utilities.HexToBinary(encryptedResponse.Nonce), EncryptionKeyPair.PrivateKey, Utilities.HexToBinary(encryptedResponse.PublicKey)));
                checkPasswordResponse = SimpleJson.DeserializeObject<CheckPasswordResponse>(clearText);
            }
            catch (Exception)
            {
            }
            return checkPasswordResponse;
        }

        private RestRequest AddHeaders(RestRequest restRequest)
        {
            var nonce = SodiumCore.GetRandomBytes(24);
            var signature = Utilities.BinaryToHex(PublicKeyAuth.SignDetached(nonce, SignaurKeyPair.PrivateKey));
            restRequest.AddHeader("X-Public", Utilities.BinaryToHex(SignaurKeyPair.PublicKey));
            restRequest.AddHeader("X-Nonce", Utilities.BinaryToHex(nonce));
            restRequest.AddHeader("X-Signature", signature);
            return restRequest;
        }
    }
}