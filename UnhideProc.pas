unit UnhideProc;

{
  UnhideProc.pas
  ----------------
  Delphi 7 port of the original C forensic tool by Yago Jesús.

  Purpose:
    • Detect hidden processes by using multiple cross-validation techniques:
        - Toolhelp snapshot enumeration (userland)
        - WMIC enumeration (WMI layer)
        - OpenProcess() brute scanning (kernel reaction)

    • Additional enhancements added in this Delphi port:
        - GetModuleBaseName (PSAPI)
        - QueryFullProcessImageName (Kernel32)
      These allow retrieving the process name and full executable path,
      which makes hidden processes easier to identify.

  Notes:
    - Requires administrator rights for best results.
    - 32-bit Delphi cannot read full info from 64-bit protected processes.
    - WMIC output parsing is very simplistic (PID-only extraction).
}

interface

uses
  Windows, SysUtils, Classes, TlHelp32;

const
  COMMAND = 'wmic process get ProcessId';
  MAX_PID = 1000000;   // Upper PID scan limit for brute OpenProcess() scan

// Procedure declarations
procedure CheckToolhelp;
procedure CheckOpen;

// Windows API declarations
function QueryFullProcessImageName(hProcess: THandle; dwFlags: DWORD; lpExeName: PChar; var lpdwSize: DWORD): BOOL; stdcall; external 'kernel32.dll' name 'QueryFullProcessImageNameA';
function GetModuleBaseName(hProcess: THandle; hModule: HMODULE; lpBaseName: PAnsiChar; nSize: DWORD): DWORD; stdcall; external 'psapi.dll' name 'GetModuleBaseNameA';

implementation

{ ------------------------------------------------------------------------- }
{  Retrieve process name using PSAPI.dll                                    }
{ ------------------------------------------------------------------------- }
function GetProcessNamepsApi(PID: DWORD): string;
var
  hProcess: THandle;
  ModName: array[0..MAX_PATH-1] of Char;
begin
  Result := '';
  // Requires PROCESS_QUERY_INFORMATION + PROCESS_VM_READ
  hProcess := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ, False, PID);
  if hProcess <> 0 then
  begin
    // Returns only the executable name (no path)
    if GetModuleBaseName(hProcess, 0, ModName, SizeOf(ModName)) > 0 then Result := ModName;
    CloseHandle(hProcess);
  end;
end;

{ ------------------------------------------------------------------------- }
{  Retrieve full executable path using QueryFullProcessImageNameA           }
{ ------------------------------------------------------------------------- }
function GetProcessNameKernel32(PID: DWORD): string;
var
  hProcess: THandle;
  Buffer: array[0..MAX_PATH-1] of Char;
  Size: DWORD;
begin
  Result := '';
  hProcess := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ, False, PID);
  if hProcess <> 0 then
  begin
    Size := MAX_PATH;
    // Returns full path (e.g. "C:\Windows\System32\svchost.exe")
    if QueryFullProcessImageName(hProcess, 0, Buffer, Size) then
      Result := Buffer
    else
      Result := '(unavailable)';
    CloseHandle(hProcess);
  end;
end;

{ ------------------------------------------------------------------------- }
{  Execute a command and capture all output lines (stdout + stderr)         }
{ ------------------------------------------------------------------------- }
function ExecReadLines(const Cmd: string; Lines: TStrings): Boolean;
var
  SA: TSecurityAttributes;
  hRead, hWrite: THandle;
  SI: TStartupInfo;
  PI: TProcessInformation;
  Buf: array[0..4095] of AnsiChar;
  BytesRead: DWORD;
  CmdLine: AnsiString;
begin
  Result := False;
  Lines.Clear;
  // Create an inheritable pipe for capturing output
  ZeroMemory(@SA, SizeOf(SA));
  SA.nLength := SizeOf(SA);
  SA.bInheritHandle := True;
  if not CreatePipe(hRead, hWrite, @SA, 0) then Exit;
  try
    // StartupInfo configuration
    ZeroMemory(@SI, SizeOf(SI));
    SI.cb := SizeOf(SI);
    SI.dwFlags := STARTF_USESTDHANDLES or STARTF_USESHOWWINDOW;
    SI.wShowWindow := SW_HIDE;
    SI.hStdOutput := hWrite;
    SI.hStdError  := hWrite;
    SI.hStdInput  := GetStdHandle(STD_INPUT_HANDLE);
    ZeroMemory(@PI, SizeOf(PI));
    CmdLine := 'cmd.exe /c ' + Cmd;
    // Launch the command
    if not CreateProcess(nil, PAnsiChar(CmdLine), nil, nil, True, CREATE_NO_WINDOW, nil, nil, SI, PI) then Exit;
    CloseHandle(hWrite); // Parent closes the write end
    try
      // Read all output
      repeat
        if not ReadFile(hRead, Buf[0], SizeOf(Buf), BytesRead, nil) then Break;
        if BytesRead = 0 then Break;
        Lines.Text := Lines.Text + String(Copy(Buf, 1, BytesRead));
      until False;
    finally
      CloseHandle(PI.hThread);
      WaitForSingleObject(PI.hProcess, 5000); // Avoid zombie processes
      CloseHandle(PI.hProcess);
    end;
    Result := Lines.Count > 0;
  finally
    CloseHandle(hRead);
  end;
end;

{ ------------------------------------------------------------------------- }
{  Extract a PID from a line of WMIC output                                 }
{ ------------------------------------------------------------------------- }
function StrToPid(const S: string): Cardinal;
var
  i: Integer;
  NumStr: string;
begin
  NumStr := '';
  // Simple digit-only extraction
  for i := 1 to Length(S) do
    if S[i] in ['0'..'9'] then
      NumStr := NumStr + S[i]
    else if (S[i] = #13) or (S[i] = #10) then
      Break;
  if NumStr = '' then
    Result := 0
  else
    Result := StrToIntDef(NumStr, 0);
end;

{ ------------------------------------------------------------------------- }
{  Compare a PID against WMIC output; report if not listed ? hidden         }
{ ------------------------------------------------------------------------- }
procedure CheckPs(tmpPid: Cardinal);
var
  Lines: TStringList;
  i: Integer;
  ok: Boolean;
  pid: Cardinal;
  pName: String;
begin
  ok := False;
  Lines := TStringList.Create;
  try
    // Fetch WMIC PID list
    if ExecReadLines(COMMAND, Lines) then
    begin
      // Linear scan: if WMIC reports the PID, it's considered visible
      for i := 0 to Lines.Count - 1 do
      begin
        pid := StrToPid(Lines[i]);
        if pid = tmpPid then
        begin
          ok := True;
          Break;
        end;
      end;
    end;
    // If WMIC did NOT see the PID ? it's a hidden process
    if not ok then
    begin
      pName := GetProcessNameKernel32(tmpPid);
      WriteLn(Format('Found HIDDEN PID: %d, Process Name: %s', [tmpPid, pName]));
    end;
  finally
    Lines.Free;
  end;
end;

{ ------------------------------------------------------------------------- }
{  Hidden process detection by brute-force OpenProcess() scanning            }
{ ------------------------------------------------------------------------- }
procedure CheckOpen;
var
  syspids: Cardinal;
  hProcess: THandle;
  lpExitCode: DWORD;
begin
  WriteLn;
  WriteLn('[*] Searching for hidden processes through OpenProcess() scan');
  WriteLn;
  // Iterate through all PID values up to MAX_PID
  for syspids := 1 to MAX_PID do
  begin
    // Scan every 4th PID to reduce overhead (as in original C code)
    if (syspids mod 4) = 0 then
    begin
      SetLastError(0);
      hProcess := OpenProcess(PROCESS_ALL_ACCESS, False, syspids);
      if hProcess <> 0 then
      begin
        lpExitCode := 0;
        // If process exists and responds, get its exit code
        if GetExitCodeProcess(hProcess, lpExitCode) then
        begin
          // Original logic: if exit code != 0 ? assume running process
          if lpExitCode <> 0 then
            CheckPs(syspids);  // Cross-check with WMIC
        end;
        CloseHandle(hProcess);
      end;
    end;
  end;
end;

{ ------------------------------------------------------------------------- }
{  Toolhelp snapshot process enumeration (userland visibility)              }
{ ------------------------------------------------------------------------- }
procedure CheckToolhelp;
var
  hSnapshot: THandle;
  pe: PROCESSENTRY32;
  pName: String;
  ok: BOOL;
begin
  WriteLn;
  WriteLn('[*] Searching for hidden processes through Toolhelp32 scan');
  WriteLn;

  hSnapshot := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if hSnapshot = INVALID_HANDLE_VALUE then
  begin
    WriteLn('CreateToolhelp32Snapshot failed: ', GetLastError);
    Exit;
  end;

  try
    ZeroMemory(@pe, SizeOf(pe));
    pe.dwSize := SizeOf(PROCESSENTRY32);
    ok := Process32First(hSnapshot, pe);
    while ok do
    begin
      // Retrieve visible name using PSAPI
      pName := GetProcessNamepsApi(pe.th32ProcessID);
      WriteLn(Format('Process ID: %d, Process Name: %s', [pe.th32ProcessID, pName]));
      // Cross-check visibility with WMIC
      CheckPs(pe.th32ProcessID);
      pe.dwSize := SizeOf(PROCESSENTRY32);
      ok := Process32Next(hSnapshot, pe);
    end;

  finally
    CloseHandle(hSnapshot);
  end;
end;

end.

