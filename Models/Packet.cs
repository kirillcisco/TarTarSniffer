﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
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
            Raw = 255,
            Spx = 1256,
            PUP = 12,
            TCP = 6,
            UDP = 17,
            UNKNOWN = -1,
            UNCPEIFIED = 0
        }

        // the original packet sniffed in the underlying layer
        private byte[] packet_Raw;

        // the sniffed time;
        private DateTime sniffedTime;

        // packet variables
        private Packet_Protocol packet_Protocol;
        private IPAddress packet_SRC_IP;
        private IPAddress packet_DEST_IP;
        private IPAddress packet_TTL;

        private int packet_SRC_PORT;
        private int packet_DEST_PORT;
        private int packet_totalLength;
        private int packet_headLength;

        public Packet(byte[] raw)
        {
            // all the following exceptions should be caught when invoking this constructor;
            if (raw == null)
                throw new ArgumentNullException();

            // when the orginal length is less than 20, it must be wrong;
            if (raw.Length < 20)
                throw new ArgumentException();

            packet_Raw = raw;

            // sniff time
            sniffedTime = DateTime.Now;

            // get the headlength in the packet;
            packet_headLength = (packet_Raw[0] & 0x0F) * 4;

            if ((raw[0] & 0x0F) < 5)
                throw new ArgumentException(); // header is wrong for the length is incorrect;

            // get packet type
            if (Enum.IsDefined(typeof(Packet_Protocol), (int)packet_Raw[9]))
                packet_Protocol = (Packet_Protocol)packet_Raw[9];
            else
                packet_Protocol = Packet_Protocol.UNCPEIFIED;

            packet_SRC_IP = new IPAddress(BitConverter.ToUInt32(packet_Raw, 12));
            packet_DEST_IP = new IPAddress(BitConverter.ToUInt32(packet_Raw, 16));
            packet_totalLength = packet_Raw[2] * 256 + packet_Raw[3];

            // handle TCP OR UDP
            if (packet_Protocol == Packet_Protocol.TCP || packet_Protocol == Packet_Protocol.UDP)
            {
                packet_SRC_PORT = packet_Raw[packet_headLength] * 256 + packet_Raw[packet_headLength + 1];
                packet_DEST_PORT = packet_Raw[packet_headLength + 2] * 256 + packet_Raw[packet_headLength + 3];

                if (packet_Protocol == Packet_Protocol.TCP)
                {
                    packet_headLength += 20;
                }
                else if (packet_Protocol == Packet_Protocol.UDP)
                {
                    packet_headLength += 8;
                }
            }
            else
            {
                packet_SRC_PORT = -404;
                packet_DEST_PORT = -404;
            }

        }
    }
}
