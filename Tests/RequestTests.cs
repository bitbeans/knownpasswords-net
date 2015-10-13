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
            const string password = "password123";
            var knownPasswords = new KnownPasswords(_clientPrivateKey);
            var response = knownPasswords.CheckPassword(password, PasswordFormatType.Cleartext);
            Assert.AreEqual(true, response.FoundPassword);
        }

        [Test]
        public void CheckPasswordBlake2b()
        {
            const string password = "password123";
            var knownPasswords = new KnownPasswords(_clientPrivateKey);
            var response = knownPasswords.CheckPassword(ApiHelper.ConvertPasswordToBlake2b(password), PasswordFormatType.Blake2b);
            Assert.AreEqual(true, response.FoundPassword);
        }

        [Test]
        public void CheckPasswordSha512()
        {
            const string password = "password123";
            var knownPasswords = new KnownPasswords(_clientPrivateKey);
            var response = knownPasswords.CheckPassword(ApiHelper.ConvertPasswordToSha512(password), PasswordFormatType.Sha512);
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
