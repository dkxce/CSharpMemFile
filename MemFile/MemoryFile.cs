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
using System.Windows;
using System.Windows.Forms;

namespace MemFile
{
    /// <summary>
    ///     Memory File
    /// </summary>
    public class MemoryFile
    {
        public static bool CONSOLE_OUT = false;

        public delegate void OnGetNotify(int msg, IntPtr caller);

        public enum FileState : byte
        {
            fsEmpty = 0,
            fsReady = 1,
            fsBusy = 2
        }

        private IncomingMessagesWindow incw = null;
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

        public OnGetNotify onGetNotify = null;

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
        public MemoryFile(string fileName, IntPtr procHandle)
        {
            FullFileName = String.Format("Global\\{0}", fileName);
            incw = new IncomingMessagesWindow(FullFileName, procHandle, new OnGetNotify(GetNotify));
            Connect();
        }

        /// <summary>
        ///     Create Memory File and Link to it
        /// </summary>
        /// <param name="fileName"></param>
        /// <param name="FileSize"></param>
        public MemoryFile(string fileName, IntPtr procHandle, uint FileSize)
        {
            this.FileSize = FileSize;
            this.FullFileSize = this.FileSize + 1;
            FullFileName = String.Format("Global\\{0}", fileName);
            incw = new IncomingMessagesWindow(FullFileName, procHandle, new OnGetNotify(GetNotify));
            Connect();
        }

        /// <summary>
        ///     File State
        /// </summary>
        private FileState intState
        {
            get
            {
                byte[] res = new byte[1];
                Marshal.Copy(ptrState, res, 0, 1);
                return (FileState)res[0];
            }
            set
            {
                byte[] res = new byte[] { (byte)value };
                Marshal.Copy(res, 0, ptrState, 1);
            }
        }

        /// <summary>
        ///     Clear File
        /// </summary>
        /// <param name="sendUpdate">send WM_APP_FileUpdated ?</param>
        public void Clear(bool sendUpdate)
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
            if (sendUpdate) SendNotifyFileUpdated();
        }

        /// <summary>
        ///     Clear File with send WM_APP_FileUpdated
        /// </summary>
        public void Clear()
        {
            this.Clear(true);
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

                SendNotifyFileConnected();
            }
            catch (Exception ex)
            {
                throw ex;
            };
        }

        /// <summary>
        ///     Get File Stream;
        ///     If you are using Stream application will not send WM_APP_FileUpdated or WM_APP_FileHandled messages
        /// </summary>
        public System.IO.Stream Stream
        {
            get
            {
                return _Stream;
            }
        }

        /// <summary>
        ///         Read/Write byte to File;
        ///         No Send WM_APP_FileUpdated or WM_APP_FileHandled Messages
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
        ///     Read/Write bytes to File;
        ///     No Send WM_APP_FileUpdated or WM_APP_FileHandled Messages
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
            this.Clear(false);
            while (this.intState == FileState.fsBusy) System.Threading.Thread.Sleep(5);
            this.intState = FileState.fsBusy;
            {
                BinaryFormatter formatter = new BinaryFormatter();
                Stream.Position = 0;
                formatter.Serialize(Stream, obj);
                Stream.Position = 0;
            };
            this.intState = FileState.fsReady;
            SendNotifyFileUpdated();
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
            SendNotifyFileHandled();
            return res;
        }

        /// <summary>
        ///     Set Object to File
        /// </summary>
        /// <param name="obj"></param>
        /// <param name="T"></param>
        public void SetSeriazable(object obj, Type T)
        {
            this.Clear(false);
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
            SendNotifyFileUpdated();
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
            SendNotifyFileHandled();
            return res;
        }

        /// <summary>
        ///     Close Memory File
        /// </summary>
        public void Close()
        {
            SendNotifyFileDisconnected();
            incw.Destroy();

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
                SendNotifyFileHandled();
                return res;
            }
            set
            {
                this.Clear(false);
                this.intState = FileState.fsReady;
                if ((value != null) && (value.Count > 0))
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
                SendNotifyFileUpdated();
                SendNotifyKeyValuesChanged();
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
                SendNotifyFileHandled();
                return System.Text.Encoding.UTF8.GetString(res).Trim('\0');
            }
            set
            {
                this.Clear(false);
                byte[] tocopy = System.Text.Encoding.UTF8.GetBytes(value);
                while (this.intState == FileState.fsBusy) System.Threading.Thread.Sleep(5);
                this.intState = FileState.fsBusy;
                {
                    Marshal.Copy(tocopy, 0, ptrStart, tocopy.Length < FileSize ? tocopy.Length : (int)FileSize);
                };
                this.intState = FileState.fsReady;
                SendNotifyFileUpdated();
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
            SendNotifyFileHandled();
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
            SendNotifyFileUpdated();
        }

        private void SendNotifyFileConnected()
        {
            SendNotify(IncomingMessagesWindow.WM_APP_FileConnected);
        }

        private void SendNotifyFileDisconnected()
        {
            SendNotify(IncomingMessagesWindow.WM_APP_FileDisconnected);
        }

        public void SendNotifyFileUpdated()
        {
            SendNotify(IncomingMessagesWindow.WM_APP_FileUpdated);
        }

        public void SendNotifyFileHandled()
        {
            SendNotify(IncomingMessagesWindow.WM_APP_FileHandled);
        }

        private void SendNotifyKeyValuesChanged()
        {
            SendNotify(IncomingMessagesWindow.WM_APP_FileKeyValuesChanged);
        }

        private void SendNotify(int msg)
        {
            if (incw == null) return;
            incw.SendMessage(msg);
        }

        private void GetNotify(int msg, IntPtr caller)
        {
            if (onGetNotify != null)
                onGetNotify(msg, caller);
            else if (MemoryFile.CONSOLE_OUT)
                Console.WriteLine("Get Notify {0} from {1}", msg, caller);
        }

        ~MemoryFile() { Close();  }

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

    [System.Security.Permissions.PermissionSet(System.Security.Permissions.SecurityAction.Demand, Name = "FullTrust")]
    internal class IncomingMessagesWindow : NativeWindow
    {
        private const int HWND_BROADCAST = 0xFFFF;

        private const int WMClose = 0x0010;
        private const int WMUser = 0x0400;
        private const int WMUMax = 0x7FFF;
        private const int WMApp = 0x8000;
        private const int WMAMax = 0xBFFF;
        private const int WMNotify = 0xC000;

        public const int WM_APP_FileConnected = WMNotify + 1;
        public const int WM_APP_FileDisconnected = WMNotify + 2;
        public const int WM_APP_FileUpdated = WMNotify + 3;
        public const int WM_APP_FileHandled = WMNotify + 4;
        public const int WM_APP_FileKeyValuesChanged = WMNotify + 5;

        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern int RegisterWindowMessage(string lpString);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        private static extern IntPtr SendMessage(IntPtr hWnd, int Msg, int wParam, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool SendNotifyMessage(IntPtr hWnd, int msg, int wParam, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool PostMessage(IntPtr hWnd, int Msg, int wParam, int lParam);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder strText, int maxCount);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowTextLength(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumWindowsProc enumProc, IntPtr lParam);

        public int _notifyMessage = WMNotify;
        private IntPtr _appHandle = IntPtr.Zero;
        private string _caption = "NoName";
        private MemoryFile.OnGetNotify _onGetNotify = null;

        public IncomingMessagesWindow(string caption, IntPtr applicationHandle, MemoryFile.OnGetNotify onGetNotify)
        {
            _caption = caption;
            _appHandle = applicationHandle;
            _notifyMessage = RegisterWindowMessage("MSG_" + _caption);
            if (MemoryFile.CONSOLE_OUT)
                Console.WriteLine("Notify Message is {0}", _notifyMessage);
            _onGetNotify = onGetNotify;

            CreateParams cp = new CreateParams();
            cp.Style = 0;
            cp.ExStyle = 0;
            cp.ClassStyle = 0;
            cp.Caption = _caption;
            //cp.Parent = IntPtr.Zero;
            CreateHandle(cp);
            if (MemoryFile.CONSOLE_OUT)
                Console.WriteLine("Window Handle is {0}\r\n", this.Handle);
        }

        private static string GetWindowText(IntPtr hWnd)
        {
            int size = GetWindowTextLength(hWnd);
            if (size > 0)
            {
                StringBuilder builder = new StringBuilder(size + 1);
                GetWindowText(hWnd, builder, builder.Capacity);
                return builder.ToString();
            }

            return String.Empty;
        }

        private static IEnumerable<IntPtr> FindWindows(EnumWindowsProc filter)
        {
            IntPtr found = IntPtr.Zero;
            List<IntPtr> windows = new List<IntPtr>();

            EnumWindows(delegate(IntPtr wnd, IntPtr param)
            {
                if (filter(wnd, param))
                {
                    // only add the windows that pass the filter
                    windows.Add(wnd);
                }

                // but return true here so that we iterate all windows
                return true;
            }, IntPtr.Zero);

            return windows;
        }

        public static IEnumerable<IntPtr> FindWindows(string titleText)
        {
            return FindWindows(delegate(IntPtr wnd, IntPtr param)
            {
                return GetWindowText(wnd).Contains(titleText);
            });
        } 

        public void SendMessage(int message)
        {
            SendNotifyMessage((IntPtr)HWND_BROADCAST, _notifyMessage, message, _appHandle);

            //IEnumerable<IntPtr> apps = FindWindows(_caption);
            //if (apps == null) return;
            //foreach (IntPtr app in apps)
            //{
            //    try
            //    {
            //        SendNotifyMessage(app, _notifyMessage, message, _appHandle);
            //        //PostMessage(app, _notifyMessage, message, (int)_appHandle);
            //        //SendMessage(app, _notifyMessage, message, _appHandle);                    
            //    }
            //    catch (Exception ex)
            //    {

            //    };
            //};
        }

        public void Destroy()
        {
            SendMessage(this.Handle, WMClose, 0, IntPtr.Zero);
            ReleaseHandle();
        }

        [System.Security.Permissions.PermissionSet(System.Security.Permissions.SecurityAction.Demand, Name = "FullTrust")]    
        protected override void WndProc(ref Message m)
        {
            // WM_USER
            if ((m.Msg >= WMUser) && (m.Msg <= WMUMax)) { };

            // WM_APP
            if ((m.Msg == WMApp) && (m.Msg <= WMAMax)) { };

            // Registered by RegisterWindowMessage
            if (m.Msg == _notifyMessage)
            {
                int msg = (int)m.WParam;
                IntPtr caller = m.LParam;
                if (MemoryFile.CONSOLE_OUT)
                {
                    if (msg == WM_APP_FileConnected) Console.WriteLine(" - file connected by {0} -", caller);
                    if (msg == WM_APP_FileDisconnected) Console.WriteLine(" - file disconnected by {0} -", caller);
                    if (msg == WM_APP_FileUpdated) Console.WriteLine(" - file updated by {0} -", caller);
                    if (msg == WM_APP_FileHandled) Console.WriteLine(" - file handled by {0} -", caller);
                    if (msg == WM_APP_FileKeyValuesChanged) Console.WriteLine(" - file keyvalues changed by {0} -", caller);
                    // ... //
                };
                if (caller != _appHandle) // not this app // LParam is Application Handle
                    if (_onGetNotify != null)
                        _onGetNotify(msg, caller);
                m.Result = (IntPtr)Handle;
            };
            base.WndProc(ref m);
        }
    }    
}
