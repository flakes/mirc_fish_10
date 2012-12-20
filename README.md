# FiSH 10
**a blowfish encryption plug-in for mIRC 7, compatible to previous FiSH scripts and other clients!**

This is an encryption addon for mIRC, it is based on FiSH v1.30 and is compatible to the
original 'blowcrypt/bloW' script as well as Mircryption and other clients.
It supports private chat, channel, topic encryption and comes with a secure key exchange
system (DH1080). In addition to the regular ECB Blowfish mode, it also supports the more
secure CBC mode.

Supported mIRC versions: mIRC 7.x only! -
	You can download the latest version from www.mirc.com

## INSTALLING

Don't shy away, the guide below is just verbose, installing is easy!

Setting up FiSH 10 should be pretty straightforward as patching mirc.exe is no longer
required. If you have been using FiSH.dll before, it is however strongly recommended
that you restore mirc.exe to its unpatched, original state before you install FiSH 10.
You can of course apply a "crack" after that, but mIRC is a good product, so if you use
it every day, I strongly advise you to get a legit lifetime license.

Alright, now on to the actual installing procedure. If you have not been using FiSH.dll
before, or if you are installing mIRC 7 from scratch, you can skip this paragraph.

1. Unload FiSH.mrc from mIRC like so: `//unload -rs $shortfn($nofile($mircexe) $+ FiSH.mrc)`
2. (Unload `blow.mrc`, `blowcrypt.mrc`, `mircryption.mrc`, etc.)
3. Delete `FiSH.dll`
4. Delete `FiSH.mrc`
5. (Delete `DH.dll` `blowfish.dll` `bloW.dll`)
6. Keep! `blow.ini`

Now that your mIRC installation is clean, we can move on to the actual installing part.

* __Download__ the latest zip file from http://github.com/flakes/mirc_fish_10/downloads
		(if you haven't already)
* __Shut down__ mIRC!
* __Extract__ fish_10.dll, fish_inject.dll and fish_10.mrc to your mirc.exe folder.
		Do the same with libeay32.dll and ssleay32.dll if your download contains them.
* If necessary, extract blow.ini-EXAMPLE and rename the file to "blow.ini".
* You can __edit fish_10.mrc__ if your blow.ini is at a different location than that folder.
	*This is useful for people who installed mIRC into Program Files but keep their settings
	in the Users/AppData folder.*
* __Start mIRC__ back up. If your mIRC is automatically connecting on startup, you might
	have to turn that off, or add a timer. It is extremely important that fish_10.mrc
	always loads before ANY IRC connection is made.
* __Install__ the script: `//load -rs $shortfn($nofile($mircexe) $+ fish_10.mrc)`
* __Shut down__ mIRC, and start it again
* Two lines like this should show up (and no error popup):

        *** FiSH 10 *** by [c&f] *** fish_inject.dll compiled XXX XX 2011 12:00:00 ***
        *** FiSH 10 *** by [c&f] *** fish_10.dll     compiled XXX XX 2011 12:00:00 ***

* If that is the case, FiSH 10 is now __ready for action__!
* __Connect__ to your networks and do your thing.

If you get an error like "/dll: unable to open file" on startup, install this:
http://www.microsoft.com/en-us/download/details.aspx?id=5582
Don't install the x64 version, even if you have a 64-bit OS. mIRC and FiSH are 32-bit,
so you need the x86 version!

If an error like "patching ... failed" shows up, something seems wrong with your setup.
It could be something simple like an incompatible OpenSSL DLL, something weird like
your AV scanner, or a bug in FiSH 10. If you made sure you installed the latest version,
you can check here for existing problem reports, or create a new one:
http://github.com/flakes/mirc_fish_10/issues
(Hint for Vista and above: Hit Ctrl + C to copy the message box contents into the clipboard,
then paste into your bug report using Ctrl + V)

When mIRC updates, FiSH 10 should just continue to work in 99% of the cases, unlike
the previous solution. And it's open source, pretty cool, he?

You can report bugs at http://github.com/flakes/mirc_fish_10/issues
or ask for help in the old FiSH.dll's forums: http://fish.secure.la/forum/
Please don't message me on IRC.

If you are an IRC enthusiast like I am, you should also check out ZNC, the best
bouncer software available: http://en.znc.in/

FiSH 10 does not contain any special code for decrypting psyBNC or sBNC logs.
Why should it? ZNC's buffers play back just fine, including appended (not prepended)
time stamps. I do consider adding support for psyBNC's network prefix thing at some
point though, since there seems to be a bunch of people actually using that.

## Multi-network support

The old FiSH never supported using different keys for #chan on NetworkOne, and #chan
on NetworkTwo. The new FiSH does fully support this while still maintaining blow.ini
backwards compatibility in all directions.

## CBC MODE

FiSH 10 implements Mircryption's CBC mode, as defined here:
www.donationcoder.com/Software/Mouser/mircryption/extra_cbcinfo.php

FiSH 10 is the first add-on to deploy a fully backwards compatible DH1080 key exchange
that AUTOMATICALLY enables the more secure CBC encryption mode if both parties use
FiSH 10. You won't notice a difference, but your messages will be encrypted stronger
than ever. Key exchanges with users of older versions and other scripts are completely
unimpaired.

There are however at least three broken DH1080 implementations that take the remainder of
the string in `DH1080_(INIT|FINISH)` instead of splitting at space characters:

* "[G]Script (OrbitIRC)" ,"Trillian Astra" and "[FiSH-irssi] (https://github.com/markusn/FiSH-irssi)".

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

FiSH 10 is using "CPatch" by armagedescu, thanks. It contains some code from
http://dirtirc.sourceforge.net/ (blowfish core) and some utility methods from
http://code.google.com/p/infekt/ (which is an excellent NFO viewer by the way).
The rest of the code is what I contributed myself and is licensed under the
"Go fuck yourself, it's free!" license.

## TECHNICAL

FiSH 10 makes heavy use of OpenSSL. It is recommended that you use the SSL libs
(ssleay32.dll and libeay32.dll) that come with the download, but other recent
libraries should work too. If they don't, FiSH 10 will let you know on startup.

You can read some lines about the in-memory patching in fish-inject.cpp. fish_inject.dll
(compiled from fish-inject.cpp, patcher.cpp and socket.cpp) does the magic of intercepting
the system calls and managing buffers. For complete lines, it calls into fish_10.dll which
does the actual IRC parsing and encryption things.
Key-exchange, getting the "outside" IP etc. is still handled by fish_10.mrc, like it
has always been.

## SECURITY NOTE

You are advised to use TrueCrypt or a similar solution to protect your blow.ini file. While all
the keys are stored encrypted, the encryption is not particularly strong and could be broken
without a lot of effort!

Furthermore, DON'T exchange keys via plaintext (IRC/email/Facebook/whatever). This defeats the
entire purpose of encryption. Instead, use DH1080 key exchange to establish a secure connection
for (channel) key exchange.

And, obviously, DO NOT store any log files on unencrypted disks.

When using DH1080, please be aware that DH1080 does NOT protect you against sophisticated man-
in-the-middle attacks where the attacker is able to read and modify your IRC data stream in
real time.
You can spot an attacker like that by using the Show key right-click menu entry, and comparing
the key contents via an absolutely man-in-the-middle-proof channel, such as via telephone or a
meeting in person.

## KNOWN ISSUES

FiSH 10 is incompatible to the following applications. Please whitelist mirc.exe in these:

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
