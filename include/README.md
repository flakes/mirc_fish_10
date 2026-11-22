Preferred: run `pwsh -File .\scripts\bootstrap-openssl.ps1` from the repository root.

That script downloads the pinned FireDaemon OpenSSL ZIP, verifies its SHA-256
checksum, and copies the matching headers into this folder. You should end up
with `include/openssl/aes.h` etc.

Manual fallback:
Copy the OpenSSL headers of the appropriate version from
https://kb.firedaemon.com/support/solutions/articles/4000121705 into this
folder.
