{
Title: Find hidden processes and TCP/UDP ports by rootkits/LKMs or other stealth techniques
Original C Author: Yago Jesús
Delphi Port: Hs32-Idir

This project is a Delphi 7 port of the original C code by Yago Jesús.
Its purpose is to detect hidden processes and stealth TCP/UDP ports typically concealed by kernel rootkits, LKMs, or other stealth mechanisms.

* Additions in the Delphi Version

The Delphi port includes extra features to retrieve:

process name
full executable path

using Windows API functions:

 -QueryFullProcessImageName
 -GetModuleBaseName

These improvements help identify and classify suspicious or hidden processes more accurately.

https://www.unhide-forensics.info
}


program unhide;

{$APPTYPE CONSOLE}

uses windows,UnhideProc,UnhideTCP;

begin
  WriteLn('Unhide 20110113');
  WriteLn('http://www.unhide-forensics.info');
  WriteLn('Ported To delphi by Hs32-Idir http : wWw.Hs32-Idir.ct.ws * wWw.Hs32-Idir.tk');
  WriteLn;

  CheckOpen;
  CheckToolhelp;
  ProcessForTCP;
  Readln;


end.