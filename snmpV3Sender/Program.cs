using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using SnmpSharpNet;

namespace snmpV3Sender
{
    class Program
    {
        static void Main(string[] args)
        {
            SnmpV3Packet packet = new SnmpV3Packet();
            // Set the security name
            packet.NoAuthNoPriv(ASCIIEncoding.UTF8.GetBytes("mysecurityname"));
            // Set your engine id
            packet.USM.EngineId.Set(new byte[] { 0x80 ,0x00 ,0x05, 0x23, 0x01, 0xc0, 0xa8, 0x8a, 0x01 });
            // Engine id is also stored in the ScopedPdu so just duplicate it
            packet.ScopedPdu.ContextEngineId.Set(packet.USM.EngineId);
            // Set your engine boots (can be 0)
            packet.USM.EngineBoots = 20;
            // Set your engine time
            packet.USM.EngineTime = 200;
            // Set message reportable flag to false. You don't really want to receive errors
            packet.MsgFlags.Reportable = false;
            // Pdu type is V2TRAP
            packet.Pdu.Type = PduType.V2Trap;
            // Set the TRAP object ID value
            packet.Pdu.TrapObjectID.Set(new int[] { 1, 3, 6, 1, 2, 1, 2, 2, 1, 0 });
            // Set your system up time value (this has nothing to do with engineTime)
            packet.Pdu.TrapSysUpTime.Value = 23456;
            // Add variable bindings to the Pdu to further describe the TRAP
            packet.Pdu.VbList.Add(new SnmpSharpNet.Oid(new int[] { 1, 3, 6, 1, 2, 1, 1, 1, 0 }), new OctetString("Test noAuthNoPriv"));
            // Finally, encode into a byte buffer ready for sending
            byte[] outBuffer = packet.encode();
            // Send it to the manager
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.SendTo(outBuffer, new IPEndPoint(IPAddress.Parse("10.6.3.30"), 162));
        }
    }
}
