using knownpasswords;
using knownpasswords.Models;
using NUnit.Framework;

namespace Tests
{
    [TestFixture]
    public class RequestTests
    {
        private readonly string _clientPrivateKey;
        public RequestTests()
        {
            _clientPrivateKey = "<your private key>";
        }
        [Test]
        public void CheckPasswordClearText()
        {
            const string cleartext = "password123";
            var knownPasswords = new KnownPasswords(_clientPrivateKey);
            var response = knownPasswords.CheckPassword(cleartext, PasswordFormatType.Cleartext);
            Assert.AreEqual(true, response.FoundPassword);
        }

        [Test]
        public void CheckPasswordBlake2b()
        {
            const string blake2b = "fbdba996cade3bae2d948c2f03f8149ffa7068584731ac6efbef1688e64609b6969a52dcc203b74aa87d6d9d1b0cd93bea724cddd12443f2b808bc03776b81cc";
            var knownPasswords = new KnownPasswords(_clientPrivateKey);
            var response = knownPasswords.CheckPassword(blake2b, PasswordFormatType.Blake2b);
            Assert.AreEqual(true, response.FoundPassword);
        }

        [Test]
        public void CheckPasswordSha512()
        {
            const string sha512 = "bed4efa1d4fdbd954bd3705d6a2a78270ec9a52ecfbfb010c61862af5c76af1761ffeb1aef6aca1bf5d02b3781aa854fabd2b69c790de74e17ecfec3cb6ac4bf";
            var knownPasswords = new KnownPasswords(_clientPrivateKey);
            var response = knownPasswords.CheckPassword(sha512, PasswordFormatType.Sha512);
            Assert.AreEqual(true, response.FoundPassword);
        }

        [Test]
        public void GetApiInformation()
        {
            var knownPasswords = new KnownPasswords(_clientPrivateKey);
            var response = knownPasswords.ApiInformation();
            Assert.GreaterOrEqual(8428008, response.Passwords);
        }
    }
}
