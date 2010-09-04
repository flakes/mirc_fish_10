;**************
;* FiSH 10 mIRC Script - Hugely based on FiSH v1.30 *
;**************
; "FiSH 10" by the way means "FiSH 2" in binary, and the year is 2010, therefore "FiSH 10".


on *:START: {
; ********** you can change the blow.ini path here if you like: **********

  set %blow_ini $shortfn($nofile($mircexe) $+ blow.ini)

; for example to use %appdata%\mIRC:
;  set %blow_ini $shortfn($mircdir $+ blow.ini)

; ***************** don't edit anything below this line. *****************

  set %FiSH_dll $shortfn($nofile($mircexe) $+ fish_10.dll)

; this call is very important:
  .dll $shortfn($nofile($mircexe) $+ fish_inject.dll) _callMe
; this one is just for info:
  .dll %FiSH_dll _callMe
; and this one is important again:
  .dll %FiSH_dll FiSH_SetIniPath %blow_ini
}


; *** auto-keyXchange ***
on *:OPEN:?:{
  if (%autokeyx == [On]) {
    var %tmp1 = $dll(%FiSH_dll,FiSH_GetKey10,$network $nick)
    if ($len(%tmp1) > 0) {
      FiSH.DH1080_INIT $nick
    }
    unset %tmp1
  }
}


; ######################################
; ### mark outgoing (own text) START ###
; *** For maximum compatibility I recommend you to disable this feature
; *** (or even delete the whole section from here)
on *:INPUT:*:{
  if (($left($1,1) == /) || (!$1) || (%mark_outgoing != [On])) return
  if ($dll(%FiSH_dll,INI_GetBool,process_outgoing) == 0) return
  if ($len($dll(%FiSH_dll,FiSH_GetKey10,$network $target)) > 1) {
    var %tmp1 = $readini %blow_ini FiSH plain_prefix
    if (%tmp1 == $null) { %tmp1 = +p }
    var %pfxlen = $len(%tmp1)
    if (%tmp1 != $left($1,%pfxlen)) {
      var %tmp1 = $readini %blow_ini FiSH mark_encrypted

      if (%mark_style == $null) { %mark_style = 2 }
      if (%tmp1 == $null) { %tmp1 = $chr(2) $+ $chr(3) $+ 12· $+ $chr(3) $+ $chr(2) }

      ;### <mynick> own encrypted text [default crypt mark] ###
      if (%mark_style == 1) {
        var %own_encrypted_text = < $+ $iif(($gettok($readini(mirc.ini, options, n2), 30, 44)) && (($me isvoice $chan) || ($me isop $chan)), $left($nick(#, $nick).pnick, 1)) $+ $nick $+ > $1- $+ $chr(32) $+ %tmp1
      }

      ;### <mynick> [default crypt mark] own encrypted text ###
      if (%mark_style == 2) {
        var %own_encrypted_text = < $+ $iif(($gettok($readini(mirc.ini, options, n2), 30, 44)) && (($me isvoice $chan) || ($me isop $chan)), $left($nick(#, $nick).pnick, 1)) $+ $nick $+ > $+ %tmp1 $1-
      }

      ;### <mynick> own encrypted text (the nick brackets are bold+blue) ###
      if (%mark_style == 3) {
        var %own_encrypted_text = $+($chr(2), $chr(3), 12<, $chr(3), $chr(2)) $+ $iif(($gettok($readini(mirc.ini, options, n2), 30, 44)) && (($me isvoice $chan) || ($me isop $chan)), $left($nick(#, $nick).pnick, 1)) $+ $nick $+ $+($chr(2), $chr(3), 12>, $chr(3), $chr(2)) $1-
      }

      echo $color(Own text) -tlbfm %own_encrypted_text
    }
    else {
      echo $color(Own text) -tlbfm < $+ $iif(($gettok($readini(mirc.ini, options, n2), 30, 44)) && (($me isvoice $chan) || ($me isop $chan)), $left($nick(#, $nick).pnick, 1)) $+ $nick $+ > $right($1-, $calc(0 - %pfxlen))
    }

    privmsg $target $1-
    halt
  }
  unset %tmp1
}
; ### mark outgoing (own text) END ###
; ####################################


on *:CONNECT:{
  if (%autoset_localip == [On]) {
    localinfo FiSH.OWNZ $dll(%FiSH_dll,FiSH_GetMyIP,FiSH)
  }
}


on *:NICK:{
  if (($nick == $me) || ($upper($newnick) == $upper($nick))) { return }
  if (($query($newnick) == $null) || (%NickTrack != [On])) { return }
  var %ky_tmp = $dll(%FiSH_dll,FiSH_GetKey10,$network $nick)
  if ($len(%ky_tmp) > 4) {
    writeini -n %blow_ini $newnick key %ky_tmp
    writeini -n %blow_ini $newnick dh1080_cbc $readini(%blow_ini,$nick,dh1080_cbc)
  }
  unset %ky_tmp
}


on ^*:NOTICE:DH1080_INIT*:?:{
  if ($len($2) > 178 && $len($2) < 182) {
    query $nick
    echo $color(Mode text) -tm $nick *** FiSH: Received DH1080 public key from $nick $+ , sending mine...
    var %tempkey $dll(%FiSH_dll,DH1080_gen,NOT_USED)
    %FiSH.prv_key = $gettok(%tempkey, 1, 32)
    %FiSH.pub_key = $gettok(%tempkey, 2, 32)
    unset %tempkey
    var %secret = $dll(%FiSH_dll,DH1080_comp, %FiSH.prv_key $2)
    if ($3 == CBC) {
      .notice $nick DH1080_FINISH %FiSH.pub_key CBC
      FiSH.setkey $nick cbc: $+ %secret
    }
    else {
      .notice $nick DH1080_FINISH %FiSH.pub_key
      FiSH.setkey $nick %secret
    }
    unset %FiSH.prv_key
    unset %FiSH.pub_key
    unset %secret
  }
  halt
}


on ^*:NOTICE:DH1080_FINISH*:?:{
  if ( %FiSH.dh [ $+ [ $nick ] ] != 1 ) {
    echo "No keyXchange in progress!"
    halt
  }
  if ($len($2) > 178 && $len($2) < 182) {
    if ($len(%FiSH.prv_key) == 180 || $len(%FiSH.prv_key) == 181) {
      var %secret = $dll(%FiSH_dll,DH1080_comp, %FiSH.prv_key $2)
      if ($3 == CBC) FiSH.setkey $nick cbc: $+ %secret
      else FiSH.setkey $nick %secret
      unset %FiSH.dh $+ [ $nick ]
      unset %FiSH.prv_key
      unset %FiSH.pub_key
      unset %secret
    }
  }
  halt
}


alias -l FiSH.WriteKey {
  if ($2 == /query) var %cur_contact = $active
  else var %cur_contact = $2
  if ($3- == $null) return

  $dll(%FiSH_dll,FiSH_WriteKey10,$1 $network %cur_contact $3-)

  var %info = *** FiSH: Key for %cur_contact set to *censored* $iif($gettok($3-,1,58) == cbc, (CBC Mode), )

  if ($window(%cur_contact) == $null) echo $color(Mode text) -at %info
  else echo $color(Mode text) -tm %cur_contact %info
}

alias FiSH.setkey { FiSH.WriteKey decode_utf8 $1 $2- }
alias FiSH.setkey_utf8 { FiSH.WriteKey raw_bytes $1 $2- }


alias FiSH.usechankey {
  var %theKey = $readini %blow_ini $2 key
  if (%theKey == $null) {
    echo $color(Mode text) -at *** FiSH: No valid key for $2 found
  }
  else {
    writeini -n %blow_ini $1 key %theKey
    writeini -n %blow_ini $1 date $date
    unset %theKey
    echo $color(Mode text) -at *** FiSH: Using same key as $2 for $1
  }
}


alias FiSH.showkey {
  if ($1 == /query) var %cur_contact = $active
  else var %cur_contact = $1

  %theKey = $dll(%FiSH_dll,FiSH_GetKey10, $network %cur_contact)
  if (%theKey != $null) {
    window -dCo +l @Blowcrypt-Key -1 -1 500 80
    aline @Blowcrypt-Key Key for %cur_contact :
    aline -p @Blowcrypt-Key %theKey
    unset %theKey
  }
  else {
    echo $color(Mode text) -at *** FiSH: No valid key for %cur_contact found
  }
}


alias FiSH.removekey {
  if ($1 == /query) var %cur_contact = $active
  else var %cur_contact = $1
  $dll(%FiSH_dll,FiSH_DelKey10,$network %cur_contact)
  echo $color(Mode text) -at *** FiSH: Key for %cur_contact has been removed
}


alias keyx { FiSH.DH1080_INIT $1 }
alias FiSH.DH1080_INIT {
  if ( ($1 == /query) || ($1 == $null) ) var %cur_contact = $active
  else var %cur_contact = $1
  set %FiSH.dh $+ [ %cur_contact ] 1
  var %tempkey $dll(%FiSH_dll,DH1080_gen,NOT_USED)
  %FiSH.prv_key = $gettok(%tempkey, 1, 32)
  %FiSH.pub_key = $gettok(%tempkey, 2, 32)
  unset %tempkey
  .NOTICE %cur_contact DH1080_INIT %FiSH.pub_key $iif($dll(%FiSH_dll,INI_GetSectionBool,$network %cur_contact dh1080_cbc 1) == 0,, CBC)
  echo $color(Mode text) -tm $nick *** FiSH: Sent my DH1080 public key to %cur_contact $+ , waiting for reply ...
}


alias FiSH.prefix {
  if ($1 != $null) {
    writeini -n %blow_ini FiSH plain_prefix $1-
    flushini mirc.ini
    echo $color(Mode text) -at *** FiSH: Plain-prefix set to $1-
  }
}

alias FiSH.showmyip {
  window -dCo +l @Local-IP -1 -1 500 80
  aline @Local-IP Your external IP address :
  aline -p @Local-IP $dll(%FiSH_dll,FiSH_GetMyIP,FiSH)
}


menu channel {
  -
  FiSH
  .Show key :FiSH.showkey $chan
  .Set new key :FiSH.setkey $chan $?
  .Set new key (UTF-8) :FiSH.setkey_utf8 $chan $?
  .Remove key :FiSH.removekey $chan
}

menu query {
  -
  FiSH
  .DH1080 keyXchange: FiSH.DH1080_INIT $1
  .-
  .Show key :FiSH.showkey $1
  .Set new key :FiSH.setkey $1 $?
  .Set new key (UTF-8) :FiSH.setkey_utf8 $1 $?
  .Remove key :FiSH.removekey $1
}

menu nicklist {
  -
  FiSH
  .DH1080 keyXchange: FiSH.DH1080_INIT $1
  .-
  .Show key :FiSH.showkey $1
  .Set new key :FiSH.setkey $1 $?
  .Set new key (UTF-8) :FiSH.setkey_utf8 $1 $?
  .Remove key :FiSH.removekey $1
  .Use same key as $chan :FiSH.usechankey $1 $chan
}

menu status,channel,nicklist,query {
  FiSH
  .-
  .Set plain-prefix $chr(91) $readini(%blow_ini,FiSH,plain_prefix) $chr(93) :FiSH.prefix $?="Enter new plain-prefix:"
  .Auto-KeyXchange $+ $chr(32) $+ %autokeyx
  ..Enable :set %autokeyx [On]
  ..Disable :set %autokeyx [Off]
  .Local IP
  ..Set local IP now: localinfo FiSH.OWNZ $dll(%FiSH_dll,FiSH_GetMyIP,FiSH)
  ..Set after connecting $+ $chr(32) $+ %autoset_localip
  ...Enable :set %autoset_localip [On]
  ...Disable :set %autoset_localip [Off]
  ..Copy local IP to clipboard: clipboard $dll(%FiSH_dll,FiSH_GetMyIP,FiSH)
  ..Show local IP :FiSH.showmyip
  .Misc config
  ..Encrypt outgoing $iif($dll(%FiSH_dll,INI_GetBool,process_outgoing) == 0, [Off], [On])
  ...Enable :writeini -n %blow_ini FiSH process_outgoing 1
  ...Disable :writeini -n %blow_ini FiSH process_outgoing 0
  ..Decrypt incoming $iif($dll(%FiSH_dll,INI_GetBool,process_incoming) == 0, [Off], [On])
  ...Enable :writeini -n %blow_ini FiSH process_incoming 1
  ...Disable :writeini -n %blow_ini FiSH process_incoming 0
  ..-
  ..Crypt-Mark (Incoming)
  ...Prefix :writeini -n %blow_ini FiSH mark_position 2
  ...Suffix :writeini -n %blow_ini FiSH mark_position 1
  ...Disable :writeini -n %blow_ini FiSH mark_position 0
  ..Crypt-Mark (Outgoing) $+ $chr(32) $+ %mark_outgoing
  ...Enable :set %mark_outgoing [On]
  ...Disable :set %mark_outgoing [Off]
  ...-
  ...Style 1 :{
    set %mark_style 1
    set %mark_outgoing [On]
  }
  ...Style 2 :{
    set %mark_style 2
    set %mark_outgoing [On]
  }
  ...Style 3 :{
    set %mark_style 3
    set %mark_outgoing [On]
  }
  ..NickTracker $+ $chr(32) $+ %NickTrack
  ...Enable :set %NickTrack [On]
  ...Disable :set %NickTrack [Off]
  ..Encrypt NOTICE $iif($dll(%FiSH_dll,INI_GetBool,encrypt_notice) == 1, [On], [Off])
  ...Enable :writeini -n %blow_ini FiSH encrypt_notice 1
  ...Disable :writeini -n %blow_ini FiSH encrypt_notice 0
  ..Encrypt ACTION $iif($dll(%FiSH_dll,INI_GetBool,encrypt_action) == 1, [On], [Off])
  ...Enable :writeini -n %blow_ini FiSH encrypt_action 1
  ...Disable :writeini -n %blow_ini FiSH encrypt_action 0
  ..-
  ..Open blow.ini :run %blow_ini
  ..-
  ..FiSH 10 - based on FiSH 1.30 by RXD :run http://github.com/flakes/mirc_fish_10
}

menu channel {
  FiSH
  .Misc config
  ..Crypt-Mark (Incoming)
  ...-
  ...Only for $chan $iif($dll(%FiSH_dll,INI_GetSectionBool,$network $chan mark_encrypted $dll(%FiSH_dll,INI_GetBool,mark_encrypted)) == 0, [Off], [On])
  ....Enable :dll %FiSH_dll INI_SetSectionBool $network $chan mark_encrypted 1
  ....Disable :dll %FiSH_dll INI_SetSectionBool $network $chan mark_encrypted 0
  ..Encrypt TOPIC $iif($dll(%FiSH_dll,INI_GetSectionBool,$network $chan encrypt_topic 0) == 1, [On], [Off])
  ...Enable :dll %FiSH_dll INI_SetSectionBool $network $chan encrypt_topic 1
  ...Disable :dll %FiSH_dll INI_SetSectionBool $network $chan encrypt_topic 0
}

menu query {
  FiSH
  .Misc config
  ..Crypt-Mark (Incoming)
  ...-
  ...Only for $1 $iif($dll(%FiSH_dll,INI_GetSectionBool,$network $1 mark_encrypted $dll(%FiSH_dll,INI_GetBool,mark_encrypted)) == 0, [Off], [On])
  ....Enable :dll %FiSH_dll INI_SetSectionBool $network $1 mark_encrypted 1
  ....Disable :dll %FiSH_dll INI_SetSectionBool $network $1 mark_encrypted 1
  ..CBC key exchange $iif($dll(%FiSH_dll,INI_GetSectionBool,$network $1 dh1080_cbc 1) == 1, [On], [Off])
  ...Enable :dll %FiSH_dll INI_SetSectionBool $network $1 dh1080_cbc 1
  ...Disable :dll %FiSH_dll INI_SetSectionBool $network $1 dh1080_cbc 0
}
