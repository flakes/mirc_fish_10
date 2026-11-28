# ReefCrypt

ReefCrypt is a Blowfish encryption plug-in for mIRC 7 based on
[FiSH 10](https://github.com/flakes/mirc_fish_10) by flakes. It interoperates with
FiSH clients, the original *blowcrypt/bloW* script, and *Mircryption*. Existing
installations use the same DLL filenames, mIRC commands, and blow.ini profiles.
It supports private chat, channel, topic encryption and comes with a secure key exchange
system (DH1080). In addition to the regular ECB Blowfish mode, it also supports the more
secure CBC mode.

## SETUP

ReefCrypt integrates with mIRC in memory and leaves the mirc.exe file on disk intact.

Furthermore, we now have an installer that handles most of the setup routine for you.
All you have to do is download and point it to the directory where your mIRC installation
is located.

The installer automatically detects whether mIRC is running in portable mode or not.
If portable mode is detected, setup won't leave any traces on your system outside
of the mIRC folder.

If you just upgraded from mIRC 6, you have to manually unload the `FiSH.mrc` file.

### DOWNLOAD

See [ReefCrypt releases](https://github.com/tsautier/ReefCrypt/releases) for packages
or [BUILD.md](BUILD.md) to compile the DLLs.

### MANUAL SETUP

In case you prefer to not use the installer for whatever reason, you can still download
a zip file. Here are the instructions to get ReefCrypt going in that case. We assume you are
running mIRC in portable mode.

* Shut down mIRC, extract all \*.dll files and fish_10.mrc to your mirc.exe folder.
* If you do not have an existing configuration file, extract blow.ini-EXAMPLE and rename it to "blow.ini".
* Start mIRC back up.
* Load the script: `//load -rs $qt($nofile($mircexe) $+ fish_10.mrc)`
* Restart mIRC.

In case you are __not__ running mIRC in portable mode, please extract the \*.dll files to
your *Program Files\mIRC* folder and the fish_10.mrc and blow.ini files to *%appdata%\mIRC*.
Use `//load -rs fish_10.mrc` to load the script.

### SECURITY INFORMATION

Please refer to the [SECURITY](SECURITY.md) document.

## TROUBLESHOOTING

* Do you have the latest release? Check the downloads page for updates.

* You have to set `load=1` under `[ssl]` in mirc.ini - the installer will do this for you.

* Use mIRC 7.73 or later.

* Check for ReefCrypt startup notices for fish_inject.dll and fish_10.dll in the mIRC status window.

* Do you use any kind of connect-on-startup script? You may have to turn that off or add a timer.
  The fish_10.mrc script MUST be loaded before any connection is made or it will not work.

* Ensure that fish_10.mrc is not loaded/started twice.

* You can check the active path to blow.ini using `//echo %blow_ini`

* For legacy ECB keys between 57 and 72 bytes, use the blow.ini option
  `enforce_max_key_length=0`. CBC keys always have a 56-byte limit.

* If an error like "*patching ... failed*" shows up, something specific to your system went wrong.
It could be something simple like an incompatible OpenSSL DLL, something weird like
your anti-virus program, or a bug in ReefCrypt. Check existing reports or open an
issue on the [ReefCrypt issue tracker](https://github.com/tsautier/ReefCrypt/issues).
(Hint for Windows Vista and above: Hit Ctrl + C to copy the message box contents into the clipboard,
then paste into your bug report using Ctrl + V)

* To dump a lot of useful debug information, use:

        /fishdebug

* Ensure that blow.ini is writable by mIRC - if it's not, you will be notified on startup.

* Known issues are listed at the end of this README.

* If you are unable to resolve your problem, you may ask for help in #fish10 on EFNet.

### OpenSSL compatibility with mIRC 7.83 and 7.85

mIRC includes its own SSL support. ReefCrypt uses the external OpenSSL 3 DLLs
for encryption and to intercept TLS reads and writes. [mIRC SSL documentation](https://www.mirc.com/ssl.html)

If ReefCrypt reports an OpenSSL error on startup, close mIRC and copy the following
files from the same FireDaemon OpenSSL 3.5 LTS ZIP to the folder containing
`mirc.exe`. Back up any existing copies before replacing them.
[FireDaemon downloads](https://kb.firedaemon.com/support/solutions/articles/4000121705)

| ZIP path | Name alongside `mirc.exe` |
| --- | --- |
| `x86/bin/libcrypto-3.dll` | `libcrypto-3.dll` |
| `x86/bin/libssl-3.dll` | `libssl-3.dll` |
| `x86/lib/ossl-modules/legacy.dll` | `libcrypto-legacy.dll` |

Set `load=1` in the `[ssl]` section of `mirc.ini`, restart mIRC, and run
`/fishdebug`. Check that `SSL ready` is `$true`, `SSL mode` is `1`, and
`GetKey10` returns `HelloWorld`. This setup was reported to work with
mIRC 7.83 using OpenSSL 3.6.0 and with mIRC 7.85 using OpenSSL 3.5.9.
[mIRC 7.83 report](https://github.com/flakes/mirc_fish_10/issues/80#issuecomment-3651525338),
[mIRC 7.85 report](https://github.com/flakes/mirc_fish_10/issues/80#issuecomment-6372411019)

## FEATURES

### MULTI-NETWORK SUPPORT

The old FiSH never supported using different keys for #chan on NetworkOne and #chan
on NetworkTwo. ReefCrypt keeps separate keys per network and continues to read existing
blow.ini profiles.

### CBC MODE

ReefCrypt implements Mircryption's CBC mode, as defined here:
www.donationcoder.com/Software/Mouser/mircryption/extra_cbcinfo.php

ReefCrypt retains FiSH 10’s DH1080 negotiation for CBC. CBC is enabled
automatically when both clients support this negotiation.

There are however at least three broken DH1080 implementations that take the remainder of
the string in `DH1080_(INIT|FINISH)` instead of splitting at space characters:

* "[G]Script (OrbitIRC)", "Trillian Astra" and "[FiSH-irssi] (https://github.com/markusn/FiSH-irssi)".

You can use the right-click menu in queries to selectively disable CBC mode key exchange
for those users. Please note that this is only a problem if you initiate the key exchange,
not if they do.

## ABOUT

fish_10.mrc is mostly a 1:1 copy of FiSH.mrc, with quite a number of modifications to
enable proper Windows Vista and 7 support, to facilitate DLL loading, for CBC mode and
multi-network awareness.

I would like to thank RXD for the work he has put into the FiSH addon over the last
few years. However, he has been slow with updates and unwilling to open source a
simple mIRC addon like this, so someone had to take over!

FiSH 10 utilizes "MinHook" by TsudaKageyu, thanks. It contains some code from
http://dirtirc.sourceforge.net/ (blowfish core) and some utility methods from
http://code.google.com/p/infekt/ (which is an excellent NFO viewer by the way).
The rest of the code is what I contributed myself and is licensed under the
"Go fuck yourself, it's free!" license.

## TECHNICAL

ReefCrypt uses three OpenSSL 3.x runtime DLLs (`libssl-3.dll`,
`libcrypto-3.dll`, and `libcrypto-legacy.dll`). ReefCrypt reports
missing or incompatible OpenSSL dependencies at startup.

For local Visual Studio builds in this repository, you can bootstrap the pinned
OpenSSL 3.5.9 package with:

    pwsh -File .\scripts\bootstrap-openssl.ps1

This downloads the current ZIP configured by the repository, verifies the
SHA-256 checksum, copies the Win32 import libraries and runtime DLLs into
`.\lib`, copies the legacy provider DLL expected by the release packaging, and
copies the headers into `.\include`. Building `fish_10` then copies the three
runtime DLLs into the selected Visual Studio output directory alongside ReefCrypt.
The Win32 toolchain, MinHook version, and build commands are documented in [BUILD.md](BUILD.md).

You can read some lines about the in-memory patching in fish-inject.cpp. fish_inject.dll
does the magic of intercepting the system calls and managing buffers. For complete lines,
it calls into fish_10.dll which does the actual IRC parsing and encryption things.
Key-exchange, getting the public IP etc. is still handled by fish_10.mrc, like it
has always been (with the help of fish_10.dll).

### Encryption DLL calls

Use `FiSH_GetKey10` with `<network> <contact> hex` to retrieve the active
key bytes as hex. CBC keys retain the `cbc:` prefix. Pass the result to
`FiSH_EncryptMsg10` or `FiSH_DecryptMsg10` as `hex_key <key> <message>`.
This preserves spaces and byte values in the key across the mIRC DLL interface.
The first space after the key separates the arguments. Additional spaces
belong to the message.

The `raw_bytes` format passes key bytes through as supplied. The legacy
`decode_utf8` format uses the Windows ANSI code page and rejects keys
that cannot be converted without changing the input.

## KNOWN ISSUES

FiSH 10 documented an incompatibility with AdMuncher because both integrate with mIRC.
If you encounter this conflict, whitelist mirc.exe in AdMuncher.

If you continue to use your old blow.ini file, and have been using a non-ANSI-compatible crypt
mark (such as the default middot "·"), using any right click menu from within mIRC will convert
your blow.ini file from ANSI to UTF-8 which will effectively destroy ReefCrypt's ability to
properly read the crypt mark.
The suggested workaround is using $chr(183) instead of "·".

When using psyBNC's multi-network feature (network prefixes), it's VITAL that you define one of
your networks as "main network". Otherwise, psyBNC won't send a NETWORK name when connecting
and all DH1080 key exchanges as well as some other things will fail silently.

## THE FUTURE

* Clean up/fix/improve .mrc file
* A feature that tries to avoid sending truncated fish messages and splits the message into
	several lines automatically (with an option to turn it off).
* Add support for Micryption's DH1080_INIT_cbc and DH1080_FINISH_cbc method.
* Make a DH1080 specs document
