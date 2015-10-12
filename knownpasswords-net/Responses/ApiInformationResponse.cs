using System;

namespace knownpasswords.Responses
{
    [Serializable]
    public class ApiInformationResponse
    {
        public string Version { get; set; }
        public long Passwords { get; set; }
    }
}