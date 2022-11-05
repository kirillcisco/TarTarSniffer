using TarTarSniffer.Models;
using TarTarSniffer.Sniffer;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace TarTarSniffer
{
    public partial class MainWindow : Form
    {
        // used to rake the underlying packets;
        List<Hypergate> hypergateList = new List<Hypergate>();

        // presenting packets;
        List<Packet> pList = new List<Packet>();

        // all sniffed packets ;
        List<Packet> allList = new List<Packet>();

        // used to refresh the packets sniffed and listView and all the related info;
        delegate void refresh(Packet p);

        // the count of the packets sniffed;
        long _totalSniffedPackets = 0;

        public MainWindow()
        {
            InitializeComponent();
        }

        private void listView1_SelectedIndexChanged(object sender, EventArgs e)
        {

        }

        private void button4_Click(object sender, EventArgs e)
        {
            Console.WriteLine("Sniffer Started");
            StartSniffer();
        }

        private void MainWindow_Load(object sender, EventArgs e)
        {

        }

        private void StartSniffer()
        {
            hypergateList.Clear();
            IPAddress[] _connectedHosts = Dns.GetHostEntry(Dns.GetHostName()).AddressList;

            if (_connectedHosts == null || _connectedHosts.Length == 0)
            {
                MessageBox.Show("No hosts");
            }
            for (int i = 0; i < _connectedHosts.Length; i++)
            {
                Hypergate hypergate = new Hypergate(_connectedHosts[i]);
                hypergateList.Add(hypergate);
            }
            foreach (Hypergate hypergate in hypergateList)
            {
                hypergate.StartMonitor();
            }
        }
    }
}