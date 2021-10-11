using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Text;
using System.Diagnostics;
using System.Xml;
using System.Runtime.Serialization.Formatters.Binary;

using System.Runtime.InteropServices;
using System.Security;
using System.Security.Permissions;
using Microsoft.Win32.SafeHandles;
using System.Runtime.ConstrainedExecution;

namespace MemFile
{
    class Program
    {
        // TEST
        static void Main(string[] args)
        {
            byte mode = 0;
            if ((args != null) && (args.Length != 0) && (args[0] == "/set")) mode = 1;
            if ((args != null) && (args.Length != 0) && (args[0] == "/get")) mode = 2;

            MemoryFile fms = new MemoryFile("SampleMemFile.bin");

            if ((mode == 0) || (mode == 1))
            {
                // Test 1 - Save/Load Object to File
                fms.SetSeriazable(new TESTCLASS((new Random()).Next(0, ushort.MaxValue), "test 1", true));
                fms.Save(MemoryFile.GetCurrentDir() + @"\file_test_1.bin");
                TESTCLASS t1 = (TESTCLASS)fms.GetSeriazable();
                Console.WriteLine("TEST 1 : TESTCLASS\r\n t1 = {0}\r\n", t1);

                // Test 2 - Save/Load Object to File
                fms.SetSeriazable(new TESTCLASS((new Random()).Next(0, ushort.MaxValue), "test 2", true), typeof(TESTCLASS));
                fms.Save(MemoryFile.GetCurrentDir() + @"\file_test_2.bin");
                TESTCLASS t2 = (TESTCLASS)fms.GetSeriazable(typeof(TESTCLASS));
                Console.WriteLine("TEST 2 : TESTCLASS\r\n t2 = {0}\r\n", t2);

                // Test 3 - Strings
                fms.AsString = "Test MemFile Sample by milokz@gmail.com";
                Console.WriteLine("TEST 3 : Strings\r\n {0}\r\n", fms.AsString);

                // Test 4 - Save/Load KeyValue Pairs to File 
                Random r = new Random();

                List<KeyValuePair<string, string>> kvp = new List<KeyValuePair<string, string>>();
                int mx = r.Next(5, 10);
                for (int i = 0; i < mx; i++)
                    kvp.Add(new KeyValuePair<string, string>(String.Format("test_{0}", r.Next(11, 99)), String.Format("{0}", r.Next(11111, 99999))));
                fms.Keys = kvp;

                fms.Save(MemoryFile.GetCurrentDir() + @"\file_test_3.bin");

            };

            List<KeyValuePair<string,string>> kvr = fms.Keys;
            Console.WriteLine("TEST 4 : Keys");
            foreach (KeyValuePair<string, string> kv in kvr)
                Console.WriteLine(" {0} = {1}", kv.Key, kv.Value);
            Console.WriteLine();            

            // End Tests
            Console.ReadLine();
            fms.Close();
        }
    }

    [Serializable]
    public class TESTCLASS
    {
        public int AAAA = -1;
        public string BBBB = "";
        public bool CCCC = false;
        public DateTime DDDD = DateTime.MinValue;

        public TESTCLASS() { }

        public TESTCLASS(int a, string b, bool c) { this.AAAA = a; this.BBBB = b; this.CCCC = c; this.DDDD = DateTime.UtcNow; }

        public override string ToString()
        {
            return String.Format("A = {0}, B = {1}, C = {2}, D = {3}", AAAA, BBBB, CCCC, DDDD);
        }
    }
       
    /// <summary>
    ///     Memory File
    /// </summary>
    public class MemoryFile
    {
        public enum FileState : byte
        {
            fsEmpty = 0,
            fsReady = 1,
            fsBusy = 2
        }

        private SafeFileMappingHandle fileHandle = null;
        private IntPtr ptrState = IntPtr.Zero;
        private IntPtr ptrStart = IntPtr.Zero;
        private IntPtr ptrParams = IntPtr.Zero;

        private string FullFileName = "Global\\NoName";
        private uint FileSize = 1048575; // for 284 keys (230 * 284 + 4 = 65324) // 1 MB
        private uint FullFileSize = 1048576;
        private System.IO.Stream _Stream;
        private bool typeFileOrKernel = false; // false - file
        private bool connected = false;

        /// <summary>
        ///     Linked to file in memory
        /// </summary>
        public bool Connected { get { return connected; } }

        /// <summary>
        ///     File Size
        /// </summary>
        public uint Size { get { return FileSize; } }

        /// <summary>
        ///     File Size in Memory
        /// </summary>
        public uint MemorySize { get { return FullFileSize; } }

        /// <summary>
        ///     Create Memory File and Link to it
        /// </summary>
        /// <param name="fileName"></param>
        public MemoryFile(string fileName)
        {
            FullFileName = String.Format("Global\\{0}", fileName);
            Connect();
        }

        /// <summary>
        ///     Create Memory File and Link to it
        /// </summary>
        /// <param name="fileName"></param>
        /// <param name="FileSize"></param>
        public MemoryFile(string fileName, uint FileSize)
        {
            this.FileSize = FileSize;
            this.FullFileSize = this.FileSize + 1;
            FullFileName = String.Format("Global\\{0}", fileName);
            Connect();
        }

        /// <summary>
        ///     File State
        /// </summary>
        private FileState intState
        {
            get {
                byte[] res = new byte[1];
                Marshal.Copy(ptrState, res, 0, 1);                
                return (FileState)res[0];
            }
            set {
                byte[] res = new byte[] { (byte)value };
                Marshal.Copy(res, 0, ptrState, 1);                
            }
        }

        /// <summary>
        ///     Clear File
        /// </summary>
        public void Clear()
        {
            while (this.intState == FileState.fsBusy) System.Threading.Thread.Sleep(5);
            this.intState = FileState.fsBusy;
            {
                byte[] b = new byte[FileSize];
                Stream.Position = 0;
                Stream.Write(b, 0, b.Length);
                Stream.Position = 0;
            };
            this.intState = FileState.fsReady;
        }

        private void Connect()
        {         
            try
            {
                SECURITY_ATTRIBUTES sa = SECURITY_ATTRIBUTES.Empty;
                fileHandle = NativeMethod.CreateFileMapping(
                    INVALID_HANDLE_VALUE,
                    ref sa, 
                    FileProtection.PAGE_READWRITE,
                    0,
                    FullFileSize, 
                    FullFileName);

                if (fileHandle.IsInvalid) throw new Win32Exception();

                //IntPtr sidPtr = IntPtr.Zero;
                //SECURITY_INFORMATION sFlags = SECURITY_INFORMATION.Owner;
                //System.Security.Principal.NTAccount user = new System.Security.Principal.NTAccount("P1R4T3\\Harris");
                //System.Security.Principal.SecurityIdentifier sid = (System.Security.Principal.SecurityIdentifier)user.Translate(typeof(System.Security.Principal.SecurityIdentifier));
                //ConvertStringSidToSid(sid.ToString(), ref sidPtr);
                SetNamedSecurityInfoW(FullFileName, typeFileOrKernel ? SE_OBJECT_TYPE.SE_KERNEL_OBJECT : SE_OBJECT_TYPE.SE_FILE_OBJECT, SECURITY_INFORMATION.Dacl, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

                ptrState = NativeMethod.MapViewOfFile(
                    fileHandle, 
                    FileMapAccess.FILE_MAP_ALL_ACCESS, 
                    0,
                    0,
                    FullFileSize
                    );

                if (ptrState == IntPtr.Zero) throw new Win32Exception();
                ptrStart = (IntPtr)((int)ptrState + 1);
                ptrParams = (IntPtr)((int)ptrStart + 4);
                
                connected = true;
                
                unsafe
                {
                    _Stream = new System.IO.UnmanagedMemoryStream((byte*)ptrStart.ToPointer(), FileSize, FileSize, System.IO.FileAccess.ReadWrite);
                };
            }
            catch (Exception ex)
            {
                throw ex;
            };
        }

        public System.IO.Stream Stream
        {
            get
            {
                return _Stream;
            }
        }

        /// <summary>
        ///         Read/Write byte to File
        /// </summary>
        /// <param name="index"></param>
        /// <returns></returns>
        public byte this[int index]
        {
            get
            {
                byte[] res = new byte[1];
                while (this.intState == FileState.fsBusy) System.Threading.Thread.Sleep(5);
                this.intState = FileState.fsBusy;
                {
                    Marshal.Copy((IntPtr)((int)ptrStart + index), res, 0, 1);
                };
                this.intState = FileState.fsReady;
                return res[0];
            }
            set
            {
                byte[] res = new byte[] { value };
                while (this.intState == FileState.fsBusy) System.Threading.Thread.Sleep(5);
                this.intState = FileState.fsBusy;
                {
                    Marshal.Copy(res, 0, (IntPtr)((int)ptrStart + index), 1);
                };
                this.intState = FileState.fsReady;
            }
        }

        /// <summary>
        ///     Read/Write bytes to File
        /// </summary>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        public byte[] this[int offset, int count]
        {
            get
            {
                byte[] res = new byte[count];
                while (this.intState == FileState.fsBusy) System.Threading.Thread.Sleep(5);
                this.intState = FileState.fsBusy;
                {
                    Marshal.Copy((IntPtr)((int)ptrStart + offset), res, 0, count);
                };
                this.intState = FileState.fsReady;
                return res;
            }
            set
            {
                while (this.intState == FileState.fsBusy) System.Threading.Thread.Sleep(5);
                this.intState = FileState.fsBusy;
                {
                    Marshal.Copy(value, 0, (IntPtr)((int)ptrStart + offset), count);
                };
                this.intState = FileState.fsReady;
            }
        }

        /// <summary>
        ///     File is Ready
        /// </summary>
        public bool IsReady
        {
            get
            {
                return (this.intState != FileState.fsBusy);
            }
        }

        /// <summary>
        ///     File is Empty
        /// </summary>
        public bool IsEmpty
        {
            get
            {
                return this.intState == FileState.fsEmpty;
            }
        }

        /// <summary>
        ///     File is Busy
        /// </summary>
        public bool IsBusy
        {
            get
            {
                return this.intState == FileState.fsBusy;
            }
        }

        /// <summary>
        ///     Set object to File
        /// </summary>
        /// <param name="obj"></param>
        public void SetSeriazable(object obj)
        {
            this.Clear();
            while (this.intState == FileState.fsBusy) System.Threading.Thread.Sleep(5);
            this.intState = FileState.fsBusy;
            {
                BinaryFormatter formatter = new BinaryFormatter();
                Stream.Position = 0;
                formatter.Serialize(Stream, obj);
                Stream.Position = 0;
            };
            this.intState = FileState.fsReady;
        }

        /// <summary>
        ///     Get object from File
        /// </summary>
        /// <returns></returns>
        public object GetSeriazable()
        {
            object res = null;
            while (this.intState == FileState.fsBusy) System.Threading.Thread.Sleep(5);
            this.intState = FileState.fsBusy;
            {
                BinaryFormatter formatter = new BinaryFormatter();
                Stream.Position = 0;
                res = formatter.Deserialize(Stream);
                Stream.Position = 0;
            };
            this.intState = FileState.fsReady;
            return res;
        }

        /// <summary>
        ///     Set Object to File
        /// </summary>
        /// <param name="obj"></param>
        /// <param name="T"></param>
        public void SetSeriazable(object obj, Type T)
        {
            this.Clear();
            while (this.intState == FileState.fsBusy) System.Threading.Thread.Sleep(5);
            this.intState = FileState.fsBusy;
            {                
                Stream.Position = 0;
                System.Xml.Serialization.XmlSerializer xs = new System.Xml.Serialization.XmlSerializer(T);
                System.IO.StreamWriter writer = new System.IO.StreamWriter(Stream);
                xs.Serialize(writer, obj);
                Stream.Position = 0;
                
            };
            this.intState = FileState.fsReady;
        }

        /// <summary>
        ///     Get Object to File
        /// </summary>
        /// <param name="T"></param>
        /// <returns></returns>
        public object GetSeriazable(Type T)
        {
            object res = null;
            while (this.intState == FileState.fsBusy) System.Threading.Thread.Sleep(5);
            this.intState = FileState.fsBusy;
            {
                Stream.Position = 0;
                System.Xml.Serialization.XmlSerializer xs = new System.Xml.Serialization.XmlSerializer(T);
                res = xs.Deserialize(Stream);
                Stream.Position = 0;
            };
            this.intState = FileState.fsReady;
            return res;
        }

        /// <summary>
        ///     Close Memory File
        /// </summary>
        public void Close()
        {
            try
            {
                _Stream.Close();
            }
            catch { };

            if (fileHandle != null)
            {
                if (ptrState != IntPtr.Zero)
                {
                    NativeMethod.UnmapViewOfFile(ptrState);
                    ptrState = IntPtr.Zero;
                };
                fileHandle.Close();
                fileHandle = null;
            };
            connected = false;
        }

        /// <summary>
        ///     Get/Set KeyValues Pairs to File
        /// </summary>
        public List<KeyValuePair<string, string>> Keys
        {
            get
            {
                List<KeyValuePair<string, string>> res = new List<KeyValuePair<string, string>>();
                {
                    int next_str_len = 0, offset = 0;
                    byte[] header = this[0, 8];
                    if (BitConverter.ToUInt64(header, 0) != 0x4b45595356414c53) return res;
                    offset += 8;
                    while ((next_str_len = BitConverter.ToInt32(this[offset, 4], 0)) > 0)
                    {
                        offset += 4;
                        string name = System.Text.Encoding.UTF8.GetString(this[offset, next_str_len]);
                        offset += next_str_len;
                        next_str_len = BitConverter.ToInt32(this[offset, 4], 0);
                        offset += 4;
                        string value = System.Text.Encoding.UTF8.GetString(this[offset, next_str_len]);
                        offset += next_str_len;
                        res.Add(new KeyValuePair<string, string>(name, value));
                    };
                };
                return res;
            }
            set
            {
                this.Clear(); 
                this.intState = FileState.fsReady;
                if ((value == null) || (value.Count == 0)) return;
                {
                    int offset = 0;
                    byte[] header = BitConverter.GetBytes(0x4b45595356414c53);
                    this[offset, header.Length] = header; offset += header.Length;
                    foreach (KeyValuePair<string, string> kvp in value)
                    {
                        byte[] na = System.Text.Encoding.UTF8.GetBytes(kvp.Key);
                        byte[] nl = BitConverter.GetBytes(na.Length);
                        byte[] va = System.Text.Encoding.UTF8.GetBytes(kvp.Value);
                        byte[] vl = BitConverter.GetBytes(va.Length);
                        byte[] nb = BitConverter.GetBytes((int)99);
                        this[offset, nl.Length] = nl; offset += nl.Length;
                        this[offset, na.Length] = na; offset += na.Length;
                        this[offset, vl.Length] = vl; offset += vl.Length;
                        this[offset, va.Length] = va; offset += va.Length;
                    };
                };
            }
        }

        /// <summary>
        ///     MemFile as TextFile
        /// </summary>
        public string AsString
        {
            get
            {
                byte[] res = new byte[FileSize];
                while (this.intState == FileState.fsBusy) System.Threading.Thread.Sleep(5);
                this.intState = FileState.fsBusy;
                {
                    Marshal.Copy(ptrStart, res, 0, res.Length);
                };
                this.intState = FileState.fsReady;
                return System.Text.Encoding.UTF8.GetString(res).Trim('\0');
            }
            set
            {
                this.Clear();
                byte[] tocopy = System.Text.Encoding.UTF8.GetBytes(value);                
                while (this.intState == FileState.fsBusy) System.Threading.Thread.Sleep(5);
                this.intState = FileState.fsBusy;
                {
                    Marshal.Copy(tocopy, 0, ptrStart, tocopy.Length < FileSize ? tocopy.Length : (int)FileSize);
                };
                this.intState = FileState.fsReady;
            }
        }

        /// <summary>
        ///     Save Memory File to Disk
        /// </summary>
        /// <param name="fileName"></param>
        public void Save(string fileName)
        {
            while (this.intState == FileState.fsBusy) System.Threading.Thread.Sleep(5);
            this.intState = FileState.fsBusy;
            {
                byte[] b = new byte[FileSize];
                Stream.Position = 0;
                Stream.Read(b, 0, b.Length);
                System.IO.FileStream fs = new System.IO.FileStream(fileName, System.IO.FileMode.Create, System.IO.FileAccess.Write);
                fs.Write(b, 0, b.Length);
                fs.Close();
            };
            this.intState = FileState.fsReady;
        }

        /// <summary>
        ///     Load Memory File From Disk
        /// </summary>
        /// <param name="fileName"></param>
        public void Load(string fileName)
        {
            while (this.intState == FileState.fsBusy) System.Threading.Thread.Sleep(5);
            this.intState = FileState.fsBusy;
            {
                byte[] b = new byte[FileSize];
                System.IO.FileStream fs = new System.IO.FileStream(fileName, System.IO.FileMode.Open, System.IO.FileAccess.Read);
                fs.Read(b, 0, b.Length);
                fs.Close();
                Stream.Position = 0;
                Stream.Write(b, 0, b.Length);
            };
            this.intState = FileState.fsReady;
         }

        ~MemoryFile() { Close(); }

        /// <summary>
        ///     Get Exe Path
        /// </summary>
        /// <returns></returns>
        public static string GetCurrentDir()
        {
            string fname = System.Reflection.Assembly.GetExecutingAssembly().GetName().CodeBase.ToString();
            fname = fname.Replace("file:///", "");
            fname = fname.Replace("/", @"\");
            fname = fname.Substring(0, fname.LastIndexOf(@"\") + 1);
            return fname;
        }

        #region Native API Signatures and Types

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        private static extern uint SetNamedSecurityInfoW(String pObjectName, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo, IntPtr psidOwner, IntPtr psidGroup, IntPtr pDacl, IntPtr pSacl);

        [DllImport("Advapi32.dll", SetLastError = true)]
        private static extern bool ConvertStringSidToSid(String StringSid, ref IntPtr Sid);

        private enum SE_OBJECT_TYPE
        {
            SE_UNKNOWN_OBJECT_TYPE = 0,
            SE_FILE_OBJECT,
            SE_SERVICE,
            SE_PRINTER,
            SE_REGISTRY_KEY,
            SE_LMSHARE,
            SE_KERNEL_OBJECT,
            SE_WINDOW_OBJECT,
            SE_DS_OBJECT,
            SE_DS_OBJECT_ALL,
            SE_PROVIDER_DEFINED_OBJECT,
            SE_WMIGUID_OBJECT,
            SE_REGISTRY_WOW64_32KEY
        }

        [Flags]
        private enum SECURITY_INFORMATION : uint
        {
            Owner = 0x00000001,
            Group = 0x00000002,
            Dacl = 0x00000004,
            Sacl = 0x00000008,
            ProtectedDacl = 0x80000000,
            ProtectedSacl = 0x40000000,
            UnprotectedDacl = 0x20000000,
            UnprotectedSacl = 0x10000000
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;

            public static SECURITY_ATTRIBUTES Empty
            {
                get
                {
                    SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                    sa.nLength = sizeof(int) * 2 + IntPtr.Size;
                    sa.lpSecurityDescriptor = IntPtr.Zero;
                    sa.bInheritHandle = 0;
                    return sa;
                }
            }
        }

        /// <summary>
        /// Memory Protection Constants
        /// http://msdn.microsoft.com/en-us/library/aa366786.aspx
        /// </summary>
        [Flags]
        public enum FileProtection : uint
        {
            NONE = 0x00,
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400,
            SEC_FILE = 0x800000,
            SEC_IMAGE = 0x1000000,
            SEC_RESERVE = 0x4000000,
            SEC_COMMIT = 0x8000000,
            SEC_NOCACHE = 0x10000000
        }


        /// <summary>
        /// Access rights for file mapping objects
        /// http://msdn.microsoft.com/en-us/library/aa366559.aspx
        /// </summary>
        [Flags]
        public enum FileMapAccess
        {
            FILE_MAP_COPY = 0x0001,
            FILE_MAP_WRITE = 0x0002,
            FILE_MAP_READ = 0x0004,
            FILE_MAP_ALL_ACCESS = 0x000F001F
        }


        /// <summary>
        /// Represents a wrapper class for a file mapping handle. 
        /// </summary>
        [SuppressUnmanagedCodeSecurity,
        HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
        internal sealed class SafeFileMappingHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            [SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
            private SafeFileMappingHandle()
                : base(true)
            {
            }

            [SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
            public SafeFileMappingHandle(IntPtr handle, bool ownsHandle)
                : base(ownsHandle)
            {
                base.SetHandle(handle);
            }

            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success),
            DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool CloseHandle(IntPtr handle);

            protected override bool ReleaseHandle()
            {
                return CloseHandle(base.handle);
            }
        }


        internal static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);


        /// <summary>
        /// The class exposes Windows APIs used in this code sample.
        /// </summary>
        [SuppressUnmanagedCodeSecurity]
        internal class NativeMethod
        {
            /// <summary>
            /// Creates or opens a named or unnamed file mapping object for a 
            /// specified file.
            /// </summary>
            /// <param name="hFile">
            /// A handle to the file from which to create a file mapping object.
            /// </param>
            /// <param name="lpAttributes">
            /// A pointer to a SECURITY_ATTRIBUTES structure that determines 
            /// whether a returned handle can be inherited by child processes.
            /// </param>
            /// <param name="flProtect">
            /// Specifies the page protection of the file mapping object. All 
            /// mapped views of the object must be compatible with this 
            /// protection.
            /// </param>
            /// <param name="dwMaximumSizeHigh">
            /// The high-order DWORD of the maximum size of the file mapping 
            /// object.
            /// </param>
            /// <param name="dwMaximumSizeLow">
            /// The low-order DWORD of the maximum size of the file mapping 
            /// object.
            /// </param>
            /// <param name="lpName">
            /// The name of the file mapping object.
            /// </param>
            /// <returns>
            /// If the function succeeds, the return value is a handle to the 
            /// newly created file mapping object.
            /// </returns>
            [DllImport("Kernel32.dll", SetLastError = true)]
            public static extern SafeFileMappingHandle CreateFileMapping(
                IntPtr hFile,
                ref SECURITY_ATTRIBUTES lpAttributes,
                FileProtection flProtect,
                uint dwMaximumSizeHigh,
                uint dwMaximumSizeLow,
                string lpName);


            /// <summary>
            /// Maps a view of a file mapping into the address space of a calling
            /// process.
            /// </summary>
            /// <param name="hFileMappingObject">
            /// A handle to a file mapping object. The CreateFileMapping and 
            /// OpenFileMapping functions return this handle.
            /// </param>
            /// <param name="dwDesiredAccess">
            /// The type of access to a file mapping object, which determines the 
            /// protection of the pages.
            /// </param>
            /// <param name="dwFileOffsetHigh">
            /// A high-order DWORD of the file offset where the view begins.
            /// </param>
            /// <param name="dwFileOffsetLow">
            /// A low-order DWORD of the file offset where the view is to begin.
            /// </param>
            /// <param name="dwNumberOfBytesToMap">
            /// The number of bytes of a file mapping to map to the view. All bytes 
            /// must be within the maximum size specified by CreateFileMapping.
            /// </param>
            /// <returns>
            /// If the function succeeds, the return value is the starting address 
            /// of the mapped view.
            /// </returns>
            [DllImport("Kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern IntPtr MapViewOfFile(
                SafeFileMappingHandle hFileMappingObject,
                FileMapAccess dwDesiredAccess,
                uint dwFileOffsetHigh,
                uint dwFileOffsetLow,
                uint dwNumberOfBytesToMap);


            /// <summary>
            /// Unmaps a mapped view of a file from the calling process's address 
            /// space.
            /// </summary>
            /// <param name="lpBaseAddress">
            /// A pointer to the base address of the mapped view of a file that 
            /// is to be unmapped.
            /// </param>
            /// <returns></returns>
            [DllImport("Kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);
        }

        #endregion
    }
}
