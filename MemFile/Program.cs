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
        private static string fileName = "SampleMemFile.bin";

        // TEST
        static void Main(string[] args)
        {
            byte mode = 0;
            if ((args != null) && (args.Length != 0) && (args[0] == "/set")) mode = 1;
            if ((args != null) && (args.Length != 0) && (args[0] == "/get")) mode = 2;


            MemoryFile.CONSOLE_OUT = true;
            IntPtr procHandle = Process.GetCurrentProcess().Handle;
            Console.WriteLine("This app handle: {0}", procHandle);
            MemoryFile fms = new MemoryFile(fileName, procHandle);

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
                fms.Save(MemoryFile.GetCurrentDir() + @"\file_test_3.bin");
                Console.WriteLine("TEST 3 : Strings\r\n {0}\r\n", fms.AsString);

                // Test 4 - Save/Load KeyValue Pairs to File 
                Random r = new Random();

                List<KeyValuePair<string, string>> kvp = new List<KeyValuePair<string, string>>();
                int mx = r.Next(5, 10);
                for (int i = 0; i < mx; i++)
                    kvp.Add(new KeyValuePair<string, string>(String.Format("test_{0}", r.Next(11, 99)), String.Format("{0}", r.Next(11111, 99999))));
                fms.Keys = kvp;
                fms.Save(MemoryFile.GetCurrentDir() + @"\file_test_4.bin");

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
         
}
