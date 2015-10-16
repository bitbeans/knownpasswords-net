# knownpasswords-net [![NuGet Version](https://img.shields.io/nuget/v/knownpasswords-net.svg?style=flat-square)](https://www.nuget.org/packages/knownpasswords-net/) [![License](http://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](https://github.com/bitbeans/knownpasswords-net/blob/master/LICENSE.md)

knownpasswords.org C# bindings

## Requirements

Just a knownpasswords.org API Key: [Get an API key](https://knownpasswords.org/)

## Installation

There is a [NuGet package](https://www.nuget.org/packages/knownpasswords-net/) available.

## Example

```csharp
	
	// check 'monkey' as Blake2b hash
	const string blake2b = "931f2b3f873fd41e0481972a7faa4ec65723867197c52d7287cc0eb0cab8c439e4ba27b427ff5dc18ae268e39a8f488a9639714cdc680964d0bd7f0133e0af24"; 
	
	var knownPasswords = new KnownPasswords("<your private API key>");
	var response = knownPasswords.CheckPassword(blake2b, PasswordFormatType.Blake2b);
	if (response.FoundPassword)
	{
		//password is a public known password
		//prevent registration or warn the user
	}
	else
	{
		//password is not known by API
		//use a KDF, encrypt the password and store it
	}
```

## Note

knownpasswords.org can validate the following password formats:

- Blake2b (64 byte hash)
- Sha512 (64 byte hash)
- Cleartext password

Never store passwords in these formats, always use a KDF (key derivation function)!
libsodium supports scrypt.

- A response never contains the cleartext password.
- The API is static and will not add requested passwords.
- Requests and responses are always signed and encrypted.
- The API is only reachable over https

## License

[MIT](https://en.wikipedia.org/wiki/MIT_License)