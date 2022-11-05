using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace TarTarSniffer.Models
{
    public class Packet
    {
        // https://learn.microsoft.com/en-us/dotnet/api/system.net.sockets.protocoltype?view=net-6.0
        enum Packet_Protocol
        {
            GGP = 3,
            ICMP = 1,
            ICMPv6 = 58,
            IDP = 22,
            IGMP = 2,
            IP = 0,
            IPv4 = 4,
            IPv6 = 41,
            IPx = 1000,
            ND = 77,
            PUP = 12,
            TCP = 6,
            UDP = 17,
            OTHERS = -1
        }

        // the original packet sniffed in the underlying layer
        private byte[] packet_Raw;

        // the sniffed time;
        private DateTime dateTime;

        // packet variables
        private Packet_Protocol packet_Protocol;
        private IPAddress packet_SRC_ip;
        private IPAddress packet_DEST_ip;
        private IPAddress packet_TTL;

        private int packet_SRC_PORT;
        private int packet_DEST_PORT;
        private int packet_totalLength;
        private int packet_headLength;
    }
}
