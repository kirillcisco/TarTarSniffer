using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using TarTarSniffer.Models;

namespace TarTarSniffer.Sniffer
{
    class Hypergate
    {

        private const int BUFFER_SIZE = 1024 * 1024;
        private const int IOC_VENDOR = 0x18000000;
        private const int IOC_IN = -2147483648; //0x80000000;
        private const int SIO_RCVALL = IOC_IN | IOC_VENDOR | 1;

        private Socket hypergate_Socket;
        private IPAddress _ipAddress;
        private byte[] hypergate_buffer;

        // https://learn.microsoft.com/ru-ru/dotnet/api/system.net.sockets.socketflags?view=net-6.0
        enum Socket_Flags
        {
            Broadcast = 1024,
            ControlDataTruncated = 512,
            DontRoute = 4,
            Multicast = 2048,
            OutOfBand = 1,
            Partial = 32768,
            Peek = 2,
            Truncated = 256,
            None = 0
        }
        private Socket_Flags socket_Flags;

        public Hypergate(IPAddress ip)
        {
            this._ipAddress = ip;
            this.hypergate_buffer = new byte[BUFFER_SIZE];
        }
        
        public void StartMonitor()
        {
            Console.WriteLine("started:  " + this._ipAddress);
            if(hypergate_Socket == null)
            {
                try
                {   
                    // ipv4 or ipv6
                    switch (_ipAddress.AddressFamily)
                    {
                        case AddressFamily.InterNetwork:
                            hypergate_Socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, System.Net.Sockets.ProtocolType.IP);
                            break;
                        case AddressFamily.InterNetworkV6:
                            hypergate_Socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, System.Net.Sockets.ProtocolType.IP);
                            break;
                        default:
                            break;
                    }

                    hypergate_Socket.Bind(new IPEndPoint(_ipAddress, 0));

                    // https://learn.microsoft.com/ru-ru/dotnet/api/system.net.sockets.socket.iocontrol?view=net-6.0
                    hypergate_Socket.IOControl(SIO_RCVALL, BitConverter.GetBytes((int)1), null);

                    hypergate_Socket.BeginReceive(hypergate_buffer, 0, hypergate_buffer.Length, SocketFlags.None, new AsyncCallback(this.OnReceive), null);;
                }
                catch (Exception e)
                {
                    hypergate_Socket.Close();
                    hypergate_Socket = null;
                    Console.WriteLine(e.ToString());
                }
            }
        }

        public void StopMonitor()
        {
            hypergate_Socket.Close();
            hypergate_Socket = null;
        }

        private void OnReceive(IAsyncResult recieved_raw)
        {
            try
            {
                int len = hypergate_Socket.EndReceive(recieved_raw);
                if (hypergate_Socket != null)
                {
                    byte[] receivedBuffer = new byte[len];
                    Array.Copy(hypergate_buffer, 0, receivedBuffer, 0, len);
                    try
                    {
                        Packet packet = new Packet(receivedBuffer);
                    }
                    catch (ArgumentNullException ane)
                    {
                        Console.WriteLine(ane.ToString());
                    }
                    catch (ArgumentException ae)
                    {
                        Console.WriteLine(ae.ToString());
                    }
                }

                hypergate_Socket.BeginReceive(hypergate_buffer, 0, hypergate_buffer.Length, SocketFlags.None, new AsyncCallback(this.OnReceive), null);
            }
            catch
            {
                StopMonitor();
            }
        }
    }
}
