; Created:20040207
; By Jeff Connelly

Name "SUMI"
OutFile "sumiinst.exe"
InstallDir "$PROGRAMFILES\SUMI"

Page components
Page directory
Page instfiles

UninstPage uninstConfirm
UninstPage instfiles

Section "SUMI (required)"
 SectionIn RO
 SetOutPath $INSTDIR
 File /r "distsumigetw\*"
 File /r "distsumiserv\*"
 File /oname=sumiserv.cfg "sumiserv.cfg.sample"
 File /oname=config.py "config.py.sample" 
 File "share\lptest"
 File /r "transport"
 File /r "client-side"
 File /r "doc"

 ; This is for Windows uninstall
 WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SUMI" "DisplayName" "SUMI 0.8.1"
 WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SUMI" "UninstallString" '"$INSTDIR\uninstall.exe"'
 WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SUMI" "NoModify" 1
 WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SUMI" "NoRepair" 1
 WriteUninstaller "uninstall.exe"
SectionEnd

Var mirc_path

; TODO: Add client-side/mirc.txt to aliases.ini
Section "mIRC Integration"
 ; Detect where mIRC was installed
 ReadRegStr $mirc_path HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\mIRC" "UninstallString"
 Call StripPath
 ;MessageBox MB_OK $mirc_path

 ; Check if aliases.ini exists
 StrCpy $mirc_path "$mirc_path\aliases.ini"
 IfFileExists $mirc_path mIRC_exists mIRC_gone

mIRC_gone:
 MessageBox MB_OK "mIRC is not installed, this option requires mIRC."
 goto mIRC_end

mIRC_exists:
 ;MessageBox MB_OK "Congratulations, you've got mIRC!"

 ; TODO: Open aliases.ini, check for ";sumi-mirc X" (version is currently 0). If
 ; not there, put it there. If version less, delete all from ;sumi-mirc to closing }.
 ; If there already, do nothing.

 ClearErrors
 FileOpen $4 $mirc_path r        ; $4=file

repeat:
 ; Check for reading ";sumi-mirc X
 FileRead $4 $1                  ; read line into $1
 IfErrors install_it            ; EOF and didn't find it
 StrCpy $3 $1 2 1                ; get XX of nXX=(lineno), assuming its >9 and <99
 Push $1                         ; search within this...
 Push ";sumi-mirc"               ; for this...
 Call StrStr                     ; find it in it
 Pop $2                          ; $2=after sumi-mirc (could be ver# in future)
 ;MessageBox MB_OK $1
 ;MessageBox MB_OK $2             ; remnants of search
 StrCmp $2 ";sumi-mirc$\r$\n" mIRC_end repeat ; found/keep searching
 ; TODO: replace old sumi-mIRCs? ver #? very complicated, remove+install..ugh

install_it:
 MessageBox MB_OK "Installing SUMI to mIRC: <$3>"
 ; SUMI-mIRC not installed! Better install it.
 FileClose $4 
 FileOpen $4 $mirc_path a
 FileSeek $4 0 END
 IntOp $3 $3 + 1       ; at last line (n)
 FileWrite $4 "$\r$3\n$3=;sumi-mirc$\r$\n"
 IntOp $3 $3 + 1
 FileWrite $4 "n$3=/sumi {$\r$\n"
 IntOp $3 $3 + 1
 FileWrite $4 "n$3=  if ($$1 != get) {$\r$\n"
 IntOp $3 $3 + 1
 FileWrite $4 "n$3=   //echo SUMI: No such command $$1$\r$\n"
 IntOp $3 $3 + 1
 FileWrite $4 "n$3=   return$\r$\n"
 IntOp $3 $3 + 1
 FileWrite $4 "n$3= }$\r$\n"
 IntOp $3 $3 + 1
 FileWrite $4 "n$3=//echo SUMI: Getting $$3 from $$2 ...$\r$\n"
 IntOp $3 $3 + 1
 FileWrite $4 'n$3= run "$INSTDIR\sumigetw" mirc $$2 $$3$\r$\n'
 IntOp $3 $3 + 1
 FileWrite $4 "n$3=}$\r$\n"
 FileClose $4


mIRC_end:
SectionEnd

;Section "File association"
; In future SUMI should be able to open .sumi or application/x-sumi's, which would have in them:
; dchantype,
; Use both MIME-type and extension:
; (from bittorrent.nsi)
; WriteRegStr HKCR .torrent "" bittorrent
; WriteRegStr HKCR .torrent "Content Type" application/x-bittorrent
; WriteRegStr HKCR "MIME\Database\Content Type\application/x-bittorrent" Extension .torrent
; WriteRegStr HKCR bittorrent "" "TORRENT File"
; WriteRegBin HKCR bittorrent EditFlags 00000100
; WriteRegStr HKCR "bittorrent\shell" "" open
; WriteRegStr HKCR "bittorrent\shell\open\command" "" `"$INSTDIR\btdownloadgui.exe" --responsefile "%1"`
; WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\BitTorrent" "DisplayName" "BitTorrent 3.3"
;  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\BitTorrent" "UninstallString" ;'"$INSTDIR\uninstall.exe"'

Section "Start Menu Shortcuts"
 CreateDirectory "$SMPROGRAMS\SUMI"
 CreateShortCut "$SMPROGRAMS\SUMI\SUMI Client.lnk" "$INSTDIR\sumigetw.exe" "" "$INSTDIR\sumigetw.exe" 0
 CreateShortCut "$SMPROGRAMS\SUMI\SUMI Server.lnk" "$INSTDIR\sumiserv.exe" "" "$INSTDIR\sumiserv.exe" 0
 CreateShortCut "$SMPROGRAMS\SUMI\Uninstall.lnk" "$INSTDIR\uninstall.exe" "" "$INSTDIR\uninstall.exe" 0
SectionEnd

Section "Uninstall"
 DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SUMI"

 Delete $INSTDIR\*

 Delete "$SMPROGRAMS\SUMI\*.*"
 RMDir "$SMPROGRAMS\SUMI"
 RMDir "$INSTDIR"
SectionEnd


 ; StrStr
 ; input, top of stack = string to search for
 ;        top of stack-1 = string to search in
 ; output, top of stack (replaces with the portion of the string remaining)
 ; modifies no other variables.
 ;
 ; Usage:
 ;   Push "this is a long ass string"
 ;   Push "ass"
 ;   Call StrStr
 ;   Pop $R0
 ;  ($R0 at this point is "ass string")

 Function StrStr
 Exch $R1 ; st=haystack,old$R1, $R1=needle
   Exch    ; st=old$R1,haystack
   Exch $R2 ; st=old$R1,old$R2, $R2=haystack
   Push $R3
   Push $R4
   Push $R5
   StrLen $R3 $R1
   StrCpy $R4 0
   ; $R1=needle
   ; $R2=haystack
   ; $R3=len(needle)
   ; $R4=cnt
   ; $R5=tmp
   loop:
     StrCpy $R5 $R2 $R3 $R4
     StrCmp $R5 $R1 done
     StrCmp $R5 "" done
     IntOp $R4 $R4 + 1
     Goto loop
 done:
   StrCpy $R1 $R2 "" $R4
   Pop $R5
   Pop $R4
   Pop $R3
   Pop $R2
   Exch $R1
 FunctionEnd

;StripPath function by Frank Nagel
;http://nsis.sourceforge.net/archive/nsisweb.php?page=379&instances=0,110
;TODO use this to find IF MIRC IS INSTALLED!
Function StripPath
  Push $1
  Push $2
  StrCmp $mirc_path "" fin

    StrCpy $1 $mirc_path 1 0 ; get firstchar
    StrCmp $1 '"' "" getparent 
      ; if first char is ", let's remove "'s first.
      StrCpy $mirc_path $mirc_path "" 1
      StrCpy $1 0
      rqloop:
        StrCpy $2 $mirc_path 1 $1
        StrCmp $2 '"' rqdone
        StrCmp $2 "" rqdone
        IntOp $1 $1 + 1
        Goto rqloop
      rqdone:
      StrCpy $mirc_path $mirc_path $1
    getparent:
    ; the uninstall string goes to an EXE, let's get the directory.
    StrCpy $1 -1
    gploop:
      StrCpy $2 $mirc_path 1 $1
      StrCmp $2 "" gpexit
      StrCmp $2 "\" gpexit
      IntOp $1 $1 - 1
      Goto gploop
    gpexit:
    StrCpy $mirc_path $mirc_path $1
    
  fin:
  Pop $2
  Pop $1
FunctionEnd

