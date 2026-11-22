# Build FiSH 10 for Win32

Use Visual Studio 2022 or Build Tools 2022 with the Desktop development with
C++ workload, a Windows 10 or 11 SDK, and PowerShell 7. The solution uses the
`v143` toolset and the `Win32` platform.

Initialize the pinned MinHook v1.3.4 submodule and bootstrap the pinned FireDaemon
OpenSSL 3.5.9 x86 dependencies from a Visual Studio Developer PowerShell at the
repository root. [MinHook v1.3.4 release](https://github.com/TsudaKageyu/minhook/releases/tag/v1.3.4),
[FireDaemon downloads](https://kb.firedaemon.com/support/solutions/articles/4000121705)

```powershell
git submodule update --init --recursive
pwsh -File .\scripts\bootstrap-openssl.ps1
msbuild .\mirc_fish_10.sln /m /p:Configuration=Release /p:Platform=Win32
```

The bootstrap verifies the ZIP's SHA-256 checksum before extracting it. The build
uses headers under `include\openssl` and import libraries `lib\libcrypto.lib`
and `lib\libssl.lib`. The MinHook source is compiled into `fish_inject.dll`.

The `Release` folder contains `fish_10.dll`, `fish_inject.dll`, `libcrypto-3.dll`,
`libssl-3.dll`, and `libcrypto-legacy.dll`. Use `Debug` or `RelWithDebInfo` in
place of `Release` to build into a folder named for that configuration. The
solution builds `fish_10` and `fish_inject` by default.

After installation, use `/fishdebug` to check SSL and test key storage.
[mIRC compatibility instructions](README.md#openssl-compatibility-with-mirc-783-and-785)
