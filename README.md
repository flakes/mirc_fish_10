# FiSH 10
**A blowfish encryption plug-in for mIRC 7, compatible with previous FiSH scripts and other clients!**

This is an encryption addon for mIRC, it is based on FiSH v1.30 and is compatible to the
original *blowcrypt/bloW* script as well as *Mircryption* and other clients.
It supports private chat, channel, topic encryption and comes with a secure key exchange
system (DH1080). In addition to the regular ECB Blowfish mode, it also supports the more
secure CBC mode.

## SETUP

FiSH 10 does no longer modify (patch) your mirc.exe file like the old FiSH addon used
to. This has the clear advantage that FiSH 10 simply continues working even after
updates to mIRC - no action required.

Furthermore, we now have an installer that handles most of the setup routine for you.
All you have to do is download and point it to the directory where your mIRC installation
is located.

The installer automatically detects whether mIRC is running in portable mode or not.
If portable mode is detected, setup won't leave any traces on your system outside
of the mIRC folder.

If you just upgraded from mIRC 6, you have to manually unload the `FiSH.mrc` file.

### DOWNLOAD

Please download the latest version from: https://syndicode.org/fish_10/

### MANUAL SETUP

In case you prefer to not use the installer for whatever reason, you can still download
a zip file. Here are the instructions to get FiSH going in that case. We assume you are
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

* For mIRC 7.35 and later, you have to set `load=1` under `[ssl]` in mirc.ini - the installer will do this for you.

* Is the script loaded correctly? If yes, these two lines will show up on mIRC startup:

        *** FiSH 10 *** by [c&f] *** fish_inject.dll compiled XXX XX 2017 12:00:00 ***
        *** FiSH 10 *** by [c&f] *** fish_10.dll     compiled XXX XX 2017 12:00:00 ***

* Do you use any kind of connect-on-startup script? You may have to turn that off or add a timer.
  The fish_10.mrc script MUST be loaded before any connection is made or it will not work.

* Ensure that fish_10.mrc is not loaded/started twice.

* You can check the active path to blow.ini using `//echo %blow_ini`

* Ensure that blow.ini is writable by mIRC - if it's not, you will be notified on startup.

* To work around keys exceeding a length of 56 bytes, the blow.ini option
  enforce_max_key_length=0
  can be used. This option is present from releases starting with 2017-02-25.

* If you run into an error like "*/dll: unable to open file*" on startup, install this:
http://www.microsoft.com/en-us/download/details.aspx?id=5582
Don't install the x64 version, even if you have a 64-bit OS. mIRC and FiSH are 32-bit,
so you need the x86 version!

* If an error like "*patching ... failed*" shows up, something specific to your system went wrong.
It could be something simple like an incompatible OpenSSL DLL, something weird like
your anti-virus program, or a bug in FiSH 10. You can check here for existing problem reports, or create a new one:
https://github.com/flakes/mirc_fish_10/issues
(Hint for Windows Vista and above: Hit Ctrl + C to copy the message box contents into the clipboard,
then paste into your bug report using Ctrl + V)

* To dump a lot of useful debug information, use:

        /fishdebug

* Known issues are listed at the end of this README.

* If you are unable to resolve your problem, you may ask for help in #fish10 on EFNet.

## FEATURES

### MULTI-NETWORK SUPPORT

The old FiSH never supported using different keys for #chan on NetworkOne and #chan
on NetworkTwo. The new FiSH does fully support this while still maintaining blow.ini
backwards compatibility in all directions.

### CBC MODE

FiSH 10 implements Mircryption's CBC mode, as defined here:
www.donationcoder.com/Software/Mouser/mircryption/extra_cbcinfo.php

FiSH 10 is the first add-on to deploy a fully backwards compatible DH1080 key exchange
that AUTOMATICALLY enables the more secure CBC encryption mode if both parties use
FiSH 10. You won't notice a difference, but your messages will be encrypted stronger
than ever. Key exchanges with users of older versions and other scripts are completely
unimpaired.

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

FiSH 10 makes heavy use of OpenSSL. It is recommended that you use the SSL libs
(ssleay32.dll and libeay32.dll) that come with the download, but other recent
libraries should work too. If they don't, FiSH 10 will let you know on startup.

You can read some lines about the in-memory patching in fish-inject.cpp. fish_inject.dll
does the magic of intercepting the system calls and managing buffers. For complete lines,
it calls into fish_10.dll which does the actual IRC parsing and encryption things.
Key-exchange, getting the public IP etc. is still handled by fish_10.mrc, like it
has always been (with the help of fish_10.dll).

## KNOWN ISSUES

FiSH 10 is incompatible with the following applications. Please whitelist mirc.exe in these:

* "AdMuncher"

This is because FiSH 10 integrates itself into mIRC similarly to these apps.

If you continue to use your old blow.ini file, and have been using a non-ANSI-compatible crypt
mark (such as the default middot "·"), using any right click menu from within mIRC will convert
your blow.ini file from ANSI to UTF-8 which will effectively destroy FiSH 10's ability to
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
