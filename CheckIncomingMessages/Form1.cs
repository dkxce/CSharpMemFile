using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using System.Runtime;
using System.Runtime.InteropServices;

using MemFile;

namespace CheckIncomingMessages
{
    public partial class Form1 : Form
    {
        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern int RegisterWindowMessage(string lpString);

        private delegate void UpText(string text);
        private MemoryFile memFile = null;        

        public Form1()
        {
            InitializeComponent();

            memFile = new MemoryFile(MemFile.Program.fileName);
            memFile.onGetNotify = GetNotify;
            memFile.ProcessNotifySources = MemoryFile.NotifySource.nsThread | MemoryFile.NotifySource.nsSystem;
        }

        private void GetNotify(MemoryFile.NotifyEvent notify, MemoryFile.NotifySource source, byte notifyParam)
        {
            string txt = String.Format("Get Notify from {2}: {0}({1})\r\n", notify, notifyParam, source);
            if(source == MemoryFile.NotifySource.nsThread)
                this.Invoke(new UpText(Update1), new object[] { txt });
            if (source == MemoryFile.NotifySource.nsSystem)
                this.Invoke(new UpText(Update2), new object[] { txt });
        }

        private void Update1(string text) { textBox1.Text += text; }
        private void Update2(string text) { textBox2.Text += text; }  
        private void Form1_FormClosing(object sender, FormClosingEventArgs e) { memFile.Close(); }
    }
}