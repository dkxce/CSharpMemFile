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
    public class Program
    {
        public const string fileName = "SampleMemFile.bin";

        // TEST
        static unsafe void Main(string[] args)
        {
            byte mode = 0;
            if ((args != null) && (args.Length != 0) && (args[0] == "/set")) mode = 1;
            if ((args != null) && (args.Length != 0) && (args[0] == "/get")) mode = 2;

            IntPtr procHandle = Process.GetCurrentProcess().Handle;
            MemoryFile fms = new MemoryFile(fileName);
            fms.ProcessNotifySources = MemoryFile.NotifySource.nsThread | MemoryFile.NotifySource.nsSystem;
            byte* firstByte = (byte*)fms.LinkAsPointer(0);
            
            if ((mode == 0) || (mode == 1))
            {
                // Test 1 - Save/Load Object to File (Bin Serialize)
                fms.SetSeriazable(new SampleClass4Serialize((new Random()).Next(0, ushort.MaxValue), "test 1", true));
                fms.Save(MemoryFile.GetCurrentDir() + @"\file_test_1.bin");
                SampleClass4Serialize t1 = (SampleClass4Serialize)fms.GetSeriazable();
                fms.SetNotifyUserEvent((byte)((new Random()).Next(1,255)));
                Console.WriteLine("TEST 1 : TESTCLASS\r\n t1 = {0} - {1}\r\n", t1, fms.DataType);

                // Test 2 - Save/Load Object to File (Xml Serialize)
                fms.SetSeriazable(new SampleClass4Serialize((new Random()).Next(0, ushort.MaxValue), "test 2", true), typeof(SampleClass4Serialize));
                fms.Save(MemoryFile.GetCurrentDir() + @"\file_test_2.bin");
                SampleClass4Serialize t2 = (SampleClass4Serialize)fms.GetSeriazable(typeof(SampleClass4Serialize));
                Console.WriteLine("TEST 2 : TESTCLASS\r\n t2 = {0} - {1}\r\n", t2, fms.DataType);

                // Test 3 - Save/Load Structure to File (Marshal)
                SampleClass4Marshal t3 = new SampleClass4Marshal(100, 200, "NoName", new string[] { "a", "b", "c" });
                fms.Set<SampleClass4Marshal>(t3);
                fms.Save(MemoryFile.GetCurrentDir() + @"\file_test_3.bin");
                SampleClass4Marshal t3r = fms.Get<SampleClass4Marshal>();
                Console.WriteLine("TEST 3 : TESTSTRUCT\r\n t3 = {0} - {1}\r\n", t3r, fms.DataType);                

                // Test 4 - Strings
                fms.AsString = "Test MemFile Sample by milokz@gmail.com";
                fms.Save(MemoryFile.GetCurrentDir() + @"\file_test_4.bin");
                Console.WriteLine("TEST 4 : Strings\r\n {0} - {1}\r\n", fms.AsString, fms.DataType);

                // Test 5 - Save/Load KeyValue Pairs to File 
                Random r = new Random();

                List<KeyValuePair<string, string>> kvp = new List<KeyValuePair<string, string>>();
                int mx = r.Next(5, 10);
                for (int i = 0; i < mx; i++)
                    kvp.Add(new KeyValuePair<string, string>(String.Format("test_{0}", r.Next(11, 99)), String.Format("{0}", r.Next(11111, 99999))));
                fms.Keys = kvp;
                fms.Save(MemoryFile.GetCurrentDir() + @"\file_test_5.bin");

            };

            List<KeyValuePair<string,string>> kvr = fms.Keys;
            Console.WriteLine("TEST 5 : Keys - {0}", fms.DataType);
            foreach (KeyValuePair<string, string> kv in kvr)
                Console.WriteLine(" {0} = {1}", kv.Key, kv.Value);
            Console.WriteLine();
           
            // End Tests
            Console.ReadLine();
            fms.Close();
        }        
    }    
}
