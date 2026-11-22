Preferred: run `pwsh -File .\scripts\bootstrap-openssl.ps1` from the repository root.

This downloads the pinned FireDaemon OpenSSL ZIP, verifies its SHA-256 checksum,
copies `x86\bin\*.dll` and `x86\lib\*.lib` into this folder, copies
`x86\lib\ossl-modules\legacy.dll` here as `libcrypto-legacy.dll`, and copies
`x86\include` into `.\include`.

Manual fallback:
Download from https://kb.firedaemon.com/support/solutions/articles/4000121705
Extract `x86\bin`
Extract `x86\lib\*.lib`
Extract `x86\include`
into this repository so that `.\lib` contains the DLL/LIB files and `.\include`
contains `openssl\aes.h` etc.
