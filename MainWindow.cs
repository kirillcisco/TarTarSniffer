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
using static System.Windows.Forms.VisualStyles.VisualStyleElement;
using System.Threading;
using System.Windows.Forms.VisualStyles;

namespace TarTarSniffer
{
    public partial class MainWindow : Form
    {
        // used to rake the underlying packets;
        List<Hypergate> hypergateList = new List<Hypergate>();

        // presenting packets;
        List<Packet> pList = new List<Packet>();

        // all sniffed packets ;
        public List<Packet> packets_List = new List<Packet>();

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
            Console.WriteLine("Selected index changed: sender: " + sender.ToString());
            System.Windows.Forms.ListView listView1 = sender as System.Windows.Forms.ListView;
            if (listView1.SelectedItems != null && listView1.SelectedItems.Count != 0)
            {
                Packet p = pList[listView1.SelectedItems[0].Index];
            }
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
                hypergate.newPacketParseEvent += new Hypergate.NewPacketParseEvent(RecieveNewPacket);
            }

            foreach (Hypergate hypergate in hypergateList)
            {
                hypergate.StartMonitor();
            }
        }

        private void RecieveNewPacket(Hypergate hypergate, Packet p)
        {
            AddPacket(p);
            //this.Invoke(new refresh(RefreshPacketsList), p);
        }

        private void RefreshPacketsList(Packet p)   
        {
            // TODO filter
            AddPacket(p);
        }

        public void AddPacket(Packet p)
        {
            Console.WriteLine("Added packet to list from: " + p.SRC_IP);
            _totalSniffedPackets++;
            packets_List.Add(p);
            this.listView1.Items.Add(new ListViewItem(new string[] {p.SRC_IP, p.SRC_PORT,p.DEST_IP, p.DEST_PORT,
                        p.PROTOCOL, p.TIME, p.LENGHT.ToString(), p.getCharString()}));
            this.listView1.EnsureVisible(listView1.Items.Count > 5 ? listView1.Items.Count - 10 : listView1.Items.Count);
        }
    }
}