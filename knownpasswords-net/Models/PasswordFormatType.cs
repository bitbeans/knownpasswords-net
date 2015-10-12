namespace knownpasswords.Models
{
    /// <summary>
    ///     Format of the password in the request.
    /// </summary>
    public enum PasswordFormatType
    {
        /// <summary>
        ///     The password is a cleartext password.
        /// </summary>
        Cleartext,

        /// <summary>
        ///     The password is a Blake2b hash (hex).
        /// </summary>
        Blake2b,

        /// <summary>
        ///     The password is a Sha512 hash (hex).
        /// </summary>
        Sha512
    }
}