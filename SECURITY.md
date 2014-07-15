# FiSH 10 - Security Information

## Short Version

**Can FiSH encryption protect me from being spyed on by the NSA?** - No, absolutely not! Sorry.

## Long Version

The following sections describe a number of known attack vectors that FiSH 10 and/or FiSH
in general are susceptible to.

### Unprotected, Unsigned Distribution

The binaries provided are not signed and not available for download via HTTPS. This means that
a third party in a network that the download is passing through may be able to modify them.

As a partial countermeasure, SHA1 hashes for current and future releases will be provided
on GitHub. Please access GitHub over a secure HTTPS connection and navigate to the following
document: https://github.com/flakes/mirc_fish_10/blob/master/HASHES

If your local files match these hashes, you probably have the official binaries.

**Could this be fixed?** - Yes, using HTTPS for downloads and a code signing certificate.

**Will this be fixed?** - No, sorry.

### No Forward Secrecy

If someone gets a hold of a channel or private message key, they are able to decrypt all previous
messages.

**Could this be fixed?** - No, it's inherent to the way FiSH has been designed.

### Weak ECB Mode as Default

The standard ECB Blowfish mode does not only provide zero forward secrecy, it also allows anyone who
is able to sniff the encrypted data to recognize repeated messages ("xxx" is always encrypted to the
same string "yyy").

ECB is generally considered broken and should in fact not be used by anyone. At all. The CBC mode that
is implemented in FiSH 10 is not vulnerable to this problem.

**Could this be fixed?** - Not in a backwards compatible way. CBC is available as alternative and can
also be used in channels using the `cbc:` key prefix.

### Replay Attacks

Both ECB and CBC mode in FiSH provide zero protection against replay attacks. If an attacker knows the
clear text to a particular cipher text, they may use that knowledge to retransmit the same message(s) again.

**Could this be fixed?** - Probably.

**Will this be fixed?** - Unlikely. Without storing deterministic nonces it's not possible to detect replay attacks.
And because there are no "sessions" (compare Forward Secrecy) it would be rather troublesome to implement securely
and impossible without breaking backwards compatibility.

### Fake Crypt Mark

If an attacker knows the crypt mark his target uses, they are able to craft a message that will appear to
have been transmitted as cipher text when in reality it was transmitted completely unencrypted.

It's also possible to append clear text to an otherwise encrypted message and still have mIRC show it the same
way as if the entire message had been encrypted. This is especially dangerous in conjunction with replay attacks.

**Could this be fixed?** - Most of it.

**Will this be fixed?** - Yes.

### No Authentication

IRC and FiSH do not provide any way to verify the remote party actually is who they claim to be.

**Could this be fixed?** - No.
