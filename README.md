# csharp-minidump
Simple C-Sharp Minidump PoC i wrote to learn a bit of C#

## Check out:
* https://github.com/slyd0g/C-Sharp-Out-Minidump
* https://www.pinvoke.net/default.aspx/Enums/ProcessAccess.html
* https://www.pinvoke.net/default.aspx/dbghelp/MiniDumpWriteDump.html
* https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass

## Usage
```
# .\csharp-minidump.exe
Usage: csharp-minidump <pid> <DumpFile>

To get the PID of the process run:
        Get-Process | Where-Object {$_.ProcessName -eq 'lsass'}
in PowerShell
```
