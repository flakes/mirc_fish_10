# FiSH 10 - Security Information

## Short Version

**Can FiSH encryption protect me from being spyed on by the NSA?** - No, absolutely not! Sorry.

## Long Version

The following sections describe a number of known attack vectors that FiSH 10 and/or FiSH
in general are susceptible to.

### Unsigned Distribution

The binaries provided are not signed. This means that a third party could provide
similar, malicious files for download and there is no integrity guarantee.

As a partial countermeasure, SHA1 hashes for current and future releases are provided
on GitHub. Please access GitHub over a secure HTTPS connection and navigate to the following
document: https://github.com/flakes/mirc_fish_10/blob/master/HASHES

If your local files match these hashes, you probably have the official binaries.

**Could this be fixed?** - Yes, using a code signing certificate.

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

### Zero Protection Against MITM Attacks

As outlined in the previous paragraphs, FiSH does absolutely nothing to protect users against man-in-the-middle (MITM)
attacks. This also includes the DH1080 key exchange procedure.

**Could this be fixed?** - No.

## Using FiSH Securely

Here's an (incomplete) list of steps that you can take to maximize the level of security provided by FiSH 10.

* Connect to IRC servers using SSL/TLS-encrypted connections exclusively.
* Try to verify the identity of your IRC server. Storing the certificate's hash on first use is a reasonable middle ground.
* Immediately assume compromise if the certificate hash changes. Verify the hash with other parties.
* If it's a private network, it's very likely for the IRC server itself to be compromised sooner or later, given the right opponent.
If the server itself is compromised, you are done. It's not possible to detect this while connecting.
* For public networks, this is less likely to happen. Try to blend in.
* Stop using ECB mode immediately, switch channels to `cbc:` keys.
* Never exchange keys plaintext (IRC/email/Facebook/whatever).
* Perform a new DH1080 key exchange for each chat session to invalidate old keys and make it impossible to decrypt old
intercepted messages with the current key. If you do this, you MUST also follow the next paragraph. Otherwise, you
will in fact lower the security level by performing new key exchanges!
* After each new DH1080 key exchange, use a telephone call or an in-person meeting to compare (verify) that your
chat partner has the same key as you have. It's not enough to compare the first or last few characters, you must compare
the entire key string.
* Put your mIRC installation and blow.ini on an encrypted file system. Use a strong password.
* Do not keep log files.
* Use LiveCDs or other non-permanent storage to make it harder to compromise your system.
* Ensure physical system security.
* Do not use FiSH if your life depends on it.
