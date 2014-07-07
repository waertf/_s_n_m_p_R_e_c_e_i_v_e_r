using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using CsvHelper;
using SnmpSharpNet;
using Gurock.SmartInspect;
namespace traprecv {
	class Program {
		static void Main(string[] args) {
		    
            SiAuto.Si.Enabled = true;
            SiAuto.Si.Level = Level.Debug;
            SiAuto.Si.Connections = @"file(filename=""" + Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + "\\log.sil\",rotate=weekly,append=true,maxparts=5,maxsize=500MB)";
            
			// Construct a socket and bind it to the trap manager port 162 
			Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
			IPEndPoint ipep = new IPEndPoint(IPAddress.Any, 162);
			EndPoint ep = (EndPoint)ipep;
			socket.Bind(ep);
			// Disable timeout processing. Just block until packet is received 
			socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 0);
			bool run = true;
			while (run) {
				byte[] indata = new byte[16 * 1024];
				// 16KB receive buffer 
                int inlen = 0;
				IPEndPoint peer = new IPEndPoint(IPAddress.Any, 0);
				EndPoint inep = (EndPoint)peer;
				try {
					inlen = socket.ReceiveFrom(indata, ref inep);
				}
			 	catch( Exception ex ) {
					Console.WriteLine("Exception {0}", ex.Message);
					inlen = -1;
				}
			 	if (inlen > 0) {
					// Check protocol version int 
					int ver = SnmpPacket.GetProtocolVersion(indata, inlen);
					if (ver == (int)SnmpVersion.Ver1) {
						// Parse SNMP Version 1 TRAP packet 
						SnmpV1TrapPacket pkt = new SnmpV1TrapPacket();
						pkt.decode(indata, inlen);
						Console.WriteLine("** SNMP Version 1 TRAP received from {0}:", inep.ToString());
						Console.WriteLine("*** Trap generic: {0}", pkt.Pdu.Generic);
						Console.WriteLine("*** Trap specific: {0}", pkt.Pdu.Specific);
						Console.WriteLine("*** Agent address: {0}", pkt.Pdu.AgentAddress.ToString());
						Console.WriteLine("*** Timestamp: {0}", pkt.Pdu.TimeStamp.ToString());
						Console.WriteLine("*** VarBind count: {0}", pkt.Pdu.VbList.Count);
						Console.WriteLine("*** VarBind content:");
						foreach (Vb v in pkt.Pdu.VbList) {
							Console.WriteLine("**** {0} {1}: {2}", v.Oid.ToString(), SnmpConstants.GetTypeName(v.Value.Type), v.Value.ToString());
						}
						Console.WriteLine("** End of SNMP Version 1 TRAP data.");
					} else {
						// Parse SNMP Version 2 TRAP packet 
                        SnmpV3Packet pkt = SnmpV3Packet.DiscoveryRequest();
						pkt.decode(indata, inlen);
						Console.WriteLine("** SNMP Version 3 TRAP received from {0}:", inep.ToString());
                        if (pkt.Version != SnmpVersion.Ver3)
                        {
							Console.WriteLine("*** NOT an SNMPv3 trap ****");
						} else {
							//Console.WriteLine("*** Community: {0}", pkt.Community.ToString());
                            StringBuilder sb = new StringBuilder();

                            Console.WriteLine(pkt.GetType());
                            Console.WriteLine(pkt.USM);
                            Console.WriteLine(pkt.USM.AuthenticationSecret);
                            Console.WriteLine(pkt.USM.PrivacySecret);
                            Console.WriteLine(pkt.Pdu.RequestId);
                            Console.WriteLine(pkt.USM.EngineId);
                            Console.WriteLine(pkt.USM.SecurityName);
                            Console.WriteLine(pkt.ScopedPdu.ContextEngineId);
                            Console.WriteLine(pkt.ScopedPdu.ContextName);
                            Console.WriteLine("trapSysUpTime.0: {0}", pkt.Pdu.TrapSysUpTime.ToString());
                            Console.WriteLine("trapObjectID.0 : {0}", pkt.Pdu.TrapObjectID.ToString());
							Console.WriteLine("*** VarBind count: {0}", pkt.Pdu.VbList.Count);
							Console.WriteLine("*** VarBind content:");
						    string serverityLevel = null, ipAddress = null, eventMessage = null,location=null;
							foreach (Vb v in pkt.Pdu.VbList) {
								Console.WriteLine("**** {0} {1}: {2}", 
								   v.Oid.ToString(), SnmpConstants.GetTypeName(v.Value.Type), v.Value.ToString());
                                sb.Append(v.Oid.ToString()).Append(" = ").Append(v.Value.ToString()).AppendLine();
							    switch (v.Oid.ToString())
							    {
                                    case "1.3.6.1.4.1.161.3.10.105.9.0"://severity level
							            serverityLevel = v.Value.ToString();
                                        break;
                                    case "1.3.6.1.4.1.161.3.10.105.8.0"://location
                                        location = v.Value.ToString();
                                        break;
                                    case "1.3.6.1.4.1.161.3.10.105.10.0"://IpAddress
							            try
							            {
                                            string ip = v.Value.ToString();
                                            string ValidIpAddressRegex = @"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";
                                            Regex r = new Regex(ValidIpAddressRegex, RegexOptions.IgnoreCase | RegexOptions.Singleline);

                                            Match m = r.Match(ip);
                                            if (m.Success)
                                            {
                                                Console.WriteLine(m.Value + " valid");
                                                ipAddress = m.Value;
                                                ipAddress = ip;
                                            }
                                            else
                                            {
                                                Console.WriteLine("invalid");
                                            }
							            }
							            catch (Exception)
							            {
							                
							                throw;
							            }
                                        break;
                                    case "1.3.6.1.4.1.161.3.10.105.13.0"://event message
                                        eventMessage = v.Value.ToString();
                                        break;
							    }
							}
						    if (serverityLevel != null && location != null && ipAddress != null && eventMessage != null)
						    {
                                using (StreamWriter sw = new StreamWriter(Environment.CurrentDirectory + "\\" + DateTime.Now.ToString("yy-MM-dd") + ".csv", true))
                                {
                                    var csv = new CsvWriter(sw);
                                    csv.WriteField(serverityLevel);
                                    csv.WriteField(location);
                                    csv.WriteField(ipAddress);
                                    csv.WriteField(eventMessage);
                                    csv.NextRecord();

                                }
						    }
                            SiAuto.Main.LogStringBuilder("receive trp",sb);
							Console.WriteLine("** End of SNMP Version 3 TRAP data.");
                            
						}
					}
				} else {
					if (inlen == 0)
						Console.WriteLine("Zero length packet received.");
				}
			}
		}

	    static DateTime convertOctetStringToDateTime(string input)
        {
            /*
            var b = "07 DE 06 1E 07 2A 16 09 2B 08 00"
.Split(' ')
.Select(s => byte.Parse(s, NumberStyles.HexNumber))
.ToArray();
            */
            var b = input
.Split(' ')
.Select(s => byte.Parse(s, NumberStyles.HexNumber))
.ToArray();

            int year = b[0] * 256 + b[1];
            int month = b[2];
            int day = b[3];
            int hour = b[4];
            int min = b[5];
            int sec = b[6];

            DateTime dt = new DateTime(year, month, day, hour, min, sec);
            //Console.WriteLine(dt);
	        return dt;
        }
	}
}