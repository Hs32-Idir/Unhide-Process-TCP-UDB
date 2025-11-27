unit UnhideTCP;

{
  UnhideTCP.pas
  -----------------------
  Delphi 7 port for detecting open and hidden TCP/UDP ports.
  
  Features:
    • Enumerates all open TCP and UDP ports using GetExtendedTcpTable / GetExtendedUdpTable.
    • Attempts to detect hidden ports by trying to bind() sockets to each port.
    • Retrieves process names associated with ports using PSAPI or QueryFullProcessImageName.
    • Supports both IPv4 TCP and UDP.

  Notes:
    - Requires administrator privileges for best accuracy.
    - Some 64-bit processes may be inaccessible from 32-bit Delphi.
    - Socket bind scanning may fail on reserved or system ports.
}

interface

uses
  Windows, SysUtils, Winsock;

const
  MAX_PORT = 65535;          // Maximum TCP/UDP port number
  MIB_TCP_STATE_LISTEN = 2;  // TCP listening state

// -------------------------------------------------------------------------
// TCP/UDP structures (Owner-PID versions)
// Compatible with Windows IPHLPAPI
// -------------------------------------------------------------------------
type
  PMIB_TCPROW_OWNER_PID = ^MIB_TCPROW_OWNER_PID;
  MIB_TCPROW_OWNER_PID = packed record
    dwState: DWORD;          // TCP state (LISTEN, ESTABLISHED, etc.)
    dwLocalAddr: DWORD;      // Local IP address
    dwLocalPort: DWORD;      // Local port (network byte order)
    dwRemoteAddr: DWORD;     // Remote IP address
    dwRemotePort: DWORD;     // Remote port
    dwOwningPid: DWORD;      // Process ID owning this socket
  end;

  PMIB_TCPTABLE_OWNER_PID = ^MIB_TCPTABLE_OWNER_PID;
  MIB_TCPTABLE_OWNER_PID = packed record
    dwNumEntries: DWORD;
    table: array[0..0] of MIB_TCPROW_OWNER_PID;
  end;

  PMIB_UDPROW_OWNER_PID = ^MIB_UDPROW_OWNER_PID;
  MIB_UDPROW_OWNER_PID = packed record
    dwLocalAddr: DWORD;
    dwLocalPort: DWORD;
    dwOwningPid: DWORD;
  end;

  PMIB_UDPTABLE_OWNER_PID = ^MIB_UDPTABLE_OWNER_PID;
  MIB_UDPTABLE_OWNER_PID = packed record
    dwNumEntries: DWORD;
    table: array[0..0] of MIB_UDPROW_OWNER_PID;
  end;

// Standard TCP/UDP tables (without PID info)
type
  PMIB_TCPROW = ^MIB_TCPROW;
  MIB_TCPROW = packed record
    dwState: DWORD;
    dwLocalAddr: DWORD;
    dwLocalPort: DWORD;
    dwRemoteAddr: DWORD;
    dwRemotePort: DWORD;
  end;

  PMIB_TCPTABLE = ^MIB_TCPTABLE;
  MIB_TCPTABLE = packed record
    dwNumEntries: DWORD;
    table: array[0..0] of MIB_TCPROW;
  end;

  PMIB_UDPROW = ^MIB_UDPROW;
  MIB_UDPROW = packed record
    dwLocalAddr: DWORD;
    dwLocalPort: DWORD;
  end;

  PMIB_UDPTABLE = ^MIB_UDPTABLE;
  MIB_UDPTABLE = packed record
    dwNumEntries: DWORD;
    table: array[0..0] of MIB_UDPROW;
  end;

// -------------------------------------------------------------------------
// External Windows API functions
// -------------------------------------------------------------------------
procedure ProcessForTCP;

function GetTcpTable(pTcpTable: PMIB_TCPTABLE; var pdwSize: DWORD; bOrder: BOOL): DWORD; stdcall; external 'iphlpapi.dll' name 'GetTcpTable';
function GetUdpTable(pUdpTable: PMIB_UDPTABLE; var pdwSize: DWORD; bOrder: BOOL): DWORD; stdcall; external 'iphlpapi.dll' name 'GetUdpTable';
function GetModuleBaseName(hProcess: THandle; hModule: HMODULE; lpBaseName: PAnsiChar; nSize: DWORD): DWORD; stdcall; external 'psapi.dll' name 'GetModuleBaseNameA';
function QueryFullProcessImageName(hProcess: THandle; dwFlags: DWORD; lpExeName: PChar; var lpdwSize: DWORD): BOOL; stdcall; external 'kernel32.dll' name 'QueryFullProcessImageNameA';
function GetExtendedTcpTable(pTcpTable: Pointer; var pdwSize: DWORD; bOrder: BOOL; ulAf: ULONG; TableClass: ULONG; Reserved: ULONG): DWORD; stdcall; external 'iphlpapi.dll';
function GetExtendedUdpTable(pUdpTable: Pointer; var pdwSize: DWORD; bOrder: BOOL; ulAf: ULONG; TableClass: ULONG; Reserved: ULONG): DWORD; stdcall; external 'iphlpapi.dll';

implementation

// -------------------------------------------------------------------------
// Retrieve process name by PID using PSAPI.dll
// -------------------------------------------------------------------------
function GetProcessNamepsApi(PID: DWORD): string;
var
  hProcess: THandle;
  ModName: array[0..MAX_PATH-1] of Char;
begin
  Result := '';
  hProcess := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ, False, PID);
  if hProcess <> 0 then
  begin
    if GetModuleBaseName(hProcess, 0, ModName, SizeOf(ModName)) > 0 then Result := ModName;
    CloseHandle(hProcess);
  end;
end;

// -------------------------------------------------------------------------
// Retrieve full executable path using QueryFullProcessImageName
// -------------------------------------------------------------------------
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
    if QueryFullProcessImageName(hProcess, 0, Buffer, Size) then
      Result := Buffer
    else
      Result := '(inaccessible)';
    CloseHandle(hProcess);
  end;
end;

// -------------------------------------------------------------------------
// Network byte order helpers
// -------------------------------------------------------------------------
function htons(x: Word): Word;
begin
  Result := ((x and $FF) shl 8) or ((x and $FF00) shr 8);
end;

function ntohs(x: Word): Word;
begin
  Result := htons(x);
end;

// -------------------------------------------------------------------------
// List open TCP ports using GetExtendedTcpTable and display owner PID
// -------------------------------------------------------------------------
procedure ListOpenTCPPortsAndMark(var TcpPorts: array of Byte);
var
  pTcpTable: PMIB_TCPTABLE_OWNER_PID;
  dwSize, dwRet: DWORD;
  i, port, pid: Integer;
  pName: string;
begin
  WriteLn('Open TCP ports through GetExtendedTcpTable()');
  WriteLn;
  dwSize := 0;
  pTcpTable := nil;
  dwRet := GetExtendedTcpTable(nil, dwSize, True, AF_INET, 5, 0); // TCP_TABLE_OWNER_PID_ALL = 5
  if dwRet = ERROR_INSUFFICIENT_BUFFER then
  begin
    pTcpTable := PMIB_TCPTABLE_OWNER_PID(HeapAlloc(GetProcessHeap, 0, dwSize));
    if pTcpTable = nil then
    begin
      WriteLn('Error allocating memory');
      Exit;
    end;
    dwRet := GetExtendedTcpTable(pTcpTable, dwSize, True, AF_INET, 5, 0);
  end;
  if dwRet = NO_ERROR then
  begin
    for i := 0 to Integer(pTcpTable^.dwNumEntries) - 1 do
    begin
      if pTcpTable^.table[i].dwState = MIB_TCP_STATE_LISTEN then
      begin
        port := ntohs(Word(pTcpTable^.table[i].dwLocalPort));
        pid := pTcpTable^.table[i].dwOwningPid;
        pName := GetProcessNameKernel32(pid);
        if pName = '' then pName := GetProcessNamePsApi(pid);
        if pName = '' then pName := '64-bit or inaccessible process';
        WriteLn(Format('TCP Port %d  PID=%d  Process=%s', [port, pid, pName]));
      end;
    end;
  end
  else
    WriteLn('GetExtendedTcpTable failed with ', dwRet);
  if pTcpTable <> nil then HeapFree(GetProcessHeap, 0, pTcpTable);
end;

// -------------------------------------------------------------------------
// Hidden TCP ports detection via bind() scanning
// -------------------------------------------------------------------------
procedure ScanHiddenTCPPorts(const TcpPorts: array of Byte);
var
  iResult: Integer;
  wsaData: TWSAData;
  service: sockaddr_in;
  ListenSocket: TSocket;
  i, z: Integer;
  pTcpTable: PMIB_TCPTABLE;
  dwSize, dwRet: DWORD;
  portFound: Integer;
begin
  WriteLn;
  WriteLn('[*]Searching for Hidden TCP ports through bind() scanning');
  WriteLn;
  if WSAStartup(MAKEWORD(2, 2), wsaData) <> 0 then
  begin
    WriteLn('Error at WSAStartup()');
    Exit;
  end;
  try
    for i := 1 to MAX_PORT do
    begin
      ListenSocket := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      if ListenSocket = INVALID_SOCKET then Break;
      FillChar(service, SizeOf(service), 0);
      service.sin_family := AF_INET;
      service.sin_addr.s_addr := inet_addr('0.0.0.0');
      service.sin_port := htons(Word(i));
      iResult := bind(ListenSocket, service, SizeOf(service));
      if iResult = SOCKET_ERROR then
      begin
        closesocket(ListenSocket);
        portFound := 0;
        // Verify via GetTcpTable
        pTcpTable := nil;
        dwSize := 0;
        dwRet := GetTcpTable(pTcpTable, dwSize, TRUE);
        if dwRet = ERROR_INSUFFICIENT_BUFFER then
        begin
          pTcpTable := PMIB_TCPTABLE(HeapAlloc(GetProcessHeap, 0, dwSize));
          if pTcpTable = nil then Exit;
          dwRet := GetTcpTable(pTcpTable, dwSize, TRUE);
          if dwRet = NO_ERROR then
          begin
            for z := 0 to Integer(pTcpTable^.dwNumEntries) - 1 do
              if ntohs(Word(pTcpTable^.table[z].dwLocalPort)) = i then
              begin
                portFound := 1;
                Break;
              end;
          end;
          HeapFree(GetProcessHeap, 0, pTcpTable);
        end;
        if portFound = 0 then WriteLn(Format('Found Hidden port %d', [i]));
      end
      else
        closesocket(ListenSocket);
    end;
  finally
    WSACleanup;
  end;
end;

// -------------------------------------------------------------------------
// List open UDP ports using GetExtendedUdpTable
// -------------------------------------------------------------------------
procedure ListOpenUDPPorts;
var
  pUdpTable: PMIB_UDPTABLE_OWNER_PID;
  dwSize, dwRet: DWORD;
  i, port, pid: Integer;
  pName: string;
begin
  WriteLn;
  WriteLn('Open UDP ports through GetExtendedUdpTable()');
  WriteLn;
  dwSize := 0;
  pUdpTable := nil;
  dwRet := GetExtendedUdpTable(nil, dwSize, True, AF_INET, 1, 0); // UDP_TABLE_OWNER_PID = 1
  if dwRet = ERROR_INSUFFICIENT_BUFFER then
  begin
    pUdpTable := PMIB_UDPTABLE_OWNER_PID(HeapAlloc(GetProcessHeap, 0, dwSize));
    if pUdpTable = nil then Exit;
    dwRet := GetExtendedUdpTable(pUdpTable, dwSize, True, AF_INET, 1, 0);
  end;
  if dwRet = NO_ERROR then
  begin
    for i := 0 to Integer(pUdpTable^.dwNumEntries) - 1 do
    begin
      port := ntohs(Word(pUdpTable^.table[i].dwLocalPort));
      pid := pUdpTable^.table[i].dwOwningPid;
      pName := GetProcessNameKernel32(pid);
      if pName = '' then pName := GetProcessNamePsApi(pid);
      if pName = '' then pName := '64-bit or inaccessible process';
      WriteLn(Format('UDP Port %d  PID=%d  Process=%s', [port, pid, pName]));
    end;
  end
  else
    WriteLn('GetExtendedUdpTable failed with ', dwRet);
  if pUdpTable <> nil then HeapFree(GetProcessHeap, 0, pUdpTable);
end;

// -------------------------------------------------------------------------
// Hidden UDP ports detection via bind() scanning
// -------------------------------------------------------------------------
procedure ScanHiddenUDPPorts;
var
  wsaData: TWSAData;
  service: sockaddr_in;
  ListenSocket: TSocket;
  iResult: Integer;
  i, z: Integer;
  pUdpTable: PMIB_UDPTABLE;
  dwSize, dwRet: DWORD;
  portFound: Integer;
  portPtr: PWORD;
begin
  WriteLn;
  WriteLn('[*]Searching for Hidden UDP ports through bind() scanning');
  WriteLn;
  if WSAStartup(MAKEWORD(2, 2), wsaData) <> 0 then Exit;
  try
    for i := 1 to MAX_PORT do
    begin
      ListenSocket := socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
      if ListenSocket = INVALID_SOCKET then Break;
      FillChar(service, SizeOf(service), 0);
      service.sin_family := AF_INET;
      service.sin_addr.s_addr := inet_addr('0.0.0.0');
      service.sin_port := htons(Word(i));
      iResult := bind(ListenSocket, service, SizeOf(service));
      if iResult = SOCKET_ERROR then
      begin
        closesocket(ListenSocket);
        portFound := 0;
        // Verify via GetUdpTable
        pUdpTable := nil;
        dwSize := 0;
        dwRet := GetUdpTable(pUdpTable, dwSize, TRUE);
        if dwRet = ERROR_INSUFFICIENT_BUFFER then
        begin
          pUdpTable := PMIB_UDPTABLE(HeapAlloc(GetProcessHeap, 0, dwSize));
          if pUdpTable = nil then Exit;
          dwRet := GetUdpTable(pUdpTable, dwSize, TRUE);
          if dwRet = NO_ERROR then
          begin
            for z := 0 to Integer(pUdpTable^.dwNumEntries) - 1 do
            begin
              portPtr := @pUdpTable^.table[z].dwLocalPort;
              if htons(portPtr^) = i then
              begin
                portFound := 1;
                Break;
              end;
            end;
          end;
          HeapFree(GetProcessHeap, 0, pUdpTable);
        end;
        if portFound = 0 then WriteLn(Format('Found Hidden port %d', [i]));
      end
      else
        closesocket(ListenSocket);
    end;
  finally
    WSACleanup;
  end;
end;

// -------------------------------------------------------------------------
// Main procedure to enumerate and scan all TCP/UDP ports
// -------------------------------------------------------------------------
procedure ProcessForTCP;
var
  TcpPorts: array[0..MAX_PORT] of Byte;
begin
  WriteLn;
  FillChar(TcpPorts, SizeOf(TcpPorts), 0);
  // Enumerate open TCP ports
  ListOpenTCPPortsAndMark(TcpPorts);
  // Scan for hidden TCP ports
  ScanHiddenTCPPorts(TcpPorts);
  // Enumerate open UDP ports
  ListOpenUDPPorts;
  // Scan for hidden UDP ports
  ScanHiddenUDPPorts;
end;

end.

