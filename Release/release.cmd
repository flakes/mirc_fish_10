@echo off

echo Copying txt files...
copy ..\NEWS NEWS.txt
copy ..\SECURITY.md SECURITY.txt
copy ..\README.md README.txt
copy ..\README.BLOWINI README.BLOWINI.txt
copy ..\blow.ini-EXAMPLE blow.ini-EXAMPLE
copy ..\fish_10.mrc fish_10.mrc

set TmpFile="tmp-date.vbs"
echo > %TmpFile% WScript.Echo "set year=" + CStr(Year(Now))
echo >> %TmpFile% WScript.Echo "set month=" + Right(100 + Month(Now), 2)
echo >> %TmpFile% WScript.Echo "set day=" + Right(100 + Day(Now), 2)
cscript /nologo "%TmpFile%" > "tmp-date.cmd"
call "tmp-date.cmd"
del "tmp-date.cmd"
del %TmpFile%

set thedate=%year%-%month%-%day%

echo Compressing [mirc_fish_10-with-ssl-%thedate%.zip] ...

zip -r -9 -T -o -q mirc_fish_10-with-ssl-%thedate%.zip blow.ini-EXAMPLE fish*.dll libcrypto-3.dll libcrypto-legacy.dll libssl-3.dll fish_10.mrc README.txt README.BLOWINI.txt NEWS.txt SECURITY.txt

echo Done

PAUSE
