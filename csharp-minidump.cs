using System.Diagnostics;
using System.Runtime.InteropServices;

namespace minidump;

//process access flags
//See: https://www.pinvoke.net/default.aspx/Enums/ProcessAccess.html
public enum ProcessAccessFlags : uint
{
    All = 0x001F0FFF,
    Terminate = 0x00000001,
    CreateThread = 0x00000002,
    VirtualMemoryOperation = 0x00000008,
    VirtualMemoryRead = 0x00000010,
    VirtualMemoryWrite = 0x00000020,
    DuplicateHandle = 0x00000040,
    CreateProcess = 0x000000080,
    SetQuota = 0x00000100,
    SetInformation = 0x00000200,
    QueryInformation = 0x00000400,
    QueryLimitedInformation = 0x00001000,
    Synchronize = 0x00100000
}

//minidump types
//See: https://github.com/slyd0g/C-Sharp-Out-Minidump
public enum MINIDUMP_TYPE
{
    MiniDumpNormal = 0x00000000,
    MiniDumpWithDataSegs = 0x00000001,
    MiniDumpWithFullMemory = 0x00000002,
    MiniDumpWithHandleData = 0x00000004,
    MiniDumpFilterMemory = 0x00000008,
    MiniDumpScanMemory = 0x00000010,
    MiniDumpWithUnloadedModules = 0x00000020,
    MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
    MiniDumpFilterModulePaths = 0x00000080,
    MiniDumpWithProcessThreadData = 0x00000100,
    MiniDumpWithPrivateReadWriteMemory = 0x00000200,
    MiniDumpWithoutOptionalData = 0x00000400,
    MiniDumpWithFullMemoryInfo = 0x00000800,
    MiniDumpWithThreadInfo = 0x00001000,
    MiniDumpWithCodeSegs = 0x00002000,
    MiniDumpWithoutAuxiliaryState = 0x00004000,
    MiniDumpWithFullAuxiliaryState = 0x00008000,
    MiniDumpWithPrivateWriteCopyMemory = 0x00010000,
    MiniDumpIgnoreInaccessibleMemory = 0x00020000,
    MiniDumpWithTokenInformation = 0x00040000,
    MiniDumpWithModuleHeaders = 0x00080000,
    MiniDumpFilterTriage = 0x00100000,
    MiniDumpValidTypeFlags = 0x001fffff
}

// Class that represents a Windows Process
// Contains the handle, PID-Information, etc., as well as the functionality to dump the process through MinidumpWriteDump
public class WindowsProcess
{
    [DllImport("dbghelp.dll", SetLastError = true)]
    static extern bool MiniDumpWriteDump(
    IntPtr hProcess,
    UInt32 ProcessId,
    SafeHandle hFile,
    MINIDUMP_TYPE DumpType,
    IntPtr ExceptionParam,
    IntPtr UserStreamParam,
    IntPtr CallbackParam);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(
      uint processAccess,
      bool bInheritHandle,
      uint processId
    );
    public static IntPtr OpenProcess(Process proc, uint flags)
    {
        return OpenProcess(flags, false, (uint)proc.Id);
    }
    private int pid;
    private System.Diagnostics.Process proc;
    private IntPtr handle;
    private bool functional = true;
    private const string errorString = "ERROR";
   
    public WindowsProcess(int pid)
    {
        this.pid = pid;

        try
        {
            this.proc = System.Diagnostics.Process.GetProcessById(pid);
            this.handle = OpenProcess(this.proc, (uint) ProcessAccessFlags.All);
        }
        catch (Exception e)
        {
            this.functional = false;
        }
    }

    public int getPid()
    {
        return this.pid;
    }

    public string getProcessName()
    {
        if (this.functional)
        {
            return this.proc.ProcessName;
        }
        else
        {
            return errorString;
        }
    }

    public IntPtr getHandle()
    {
        if (this.functional)
        {
            return this.handle;
        }
        else
        {
            return this.handle;
        }
    }

    //Returns the information, wether the object is functional or defunct (i.e. if currently a running process with the supplied PID exists)
    public bool getFunctionality()
    {
        return this.functional;
    }

    //Create a Minidump-File of the process that corresponds to the Object and save it inside the specified path
    public bool dump(string path)
    {
        if(this.functional && this.handle.ToInt64() != 0)
        {
            FileStream file = File.Create(path);
            bool ret = MiniDumpWriteDump(this.handle, (uint)this.proc.Id, file.SafeFileHandle, MINIDUMP_TYPE.MiniDumpWithFullMemory, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            file.Close();
            return ret;
        }
        else
        {
            return false;
        }
    }
}
class Hello
{
    static void Main(string[] args)
    {
        if(args.Length != 2)
        {
            System.Console.WriteLine("Usage: " + System.AppDomain.CurrentDomain.FriendlyName + " <pid> <DumpFile>");
            System.Console.WriteLine("\nTo get the PID of the process run:\n\tGet-Process | Where-Object {$_.ProcessName -eq 'lsass'}\nin PowerShell");
            return;
        }

        int pid = Int32.Parse(args[0]);
        string path = args[1]; 
        
        WindowsProcess p = new WindowsProcess(pid);

        if(p.getFunctionality())
        {
            System.Console.WriteLine("Attempting to dump process " + p.getProcessName() + " (PID: " + p.getPid() + ")...");
            if(p.dump(path)) {
                System.Console.WriteLine("Minidump created successfully!");
            }
            else
            {
                System.Console.WriteLine("ERROR: Minidump could not be created!");
            }
        }
        else
        {
            System.Console.WriteLine("ERROR: Please recheck the supplied PID!");
        }
    }
}
