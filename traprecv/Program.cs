using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Timers;
using CsvHelper;
using SnmpSharpNet;
using Gurock.SmartInspect;
namespace traprecv {
	class Program {
        static SqlClient pgsqSqlClient = new SqlClient(
                ConfigurationManager.AppSettings["SQL_SERVER_IP"],
                ConfigurationManager.AppSettings["SQL_SERVER_PORT"],
                ConfigurationManager.AppSettings["SQL_SERVER_USER_ID"],
                ConfigurationManager.AppSettings["SQL_SERVER_PASSWORD"],
                ConfigurationManager.AppSettings["SQL_SERVER_DATABASE"]
                );
        static SqlClient smsSqlClient = new SqlClient(
            ConfigurationManager.AppSettings["SMS_SERVER_IP"],
                ConfigurationManager.AppSettings["SMS_SERVER_PORT"],
                ConfigurationManager.AppSettings["SMS_SERVER_USER_ID"],
                ConfigurationManager.AppSettings["SMS_SERVER_PASSWORD"],
                ConfigurationManager.AppSettings["SMS_SERVER_DATABASE"]);
        private static readonly string m_sender = "拓樸系統管理者";
        static ConcurrentQueue<string> smsQueue = new ConcurrentQueue<string>(); 
        static StringBuilder smsSB = new StringBuilder("test");
        private static string sendSMS = ConfigurationManager.AppSettings["sendSMS"];
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
            #region sms
            var smsSendTimer = new System.Timers.Timer(5);
            smsSendTimer.Elapsed += (sender, e) =>
            {
                string result = null;
                string deviceName = null;
                string stateId = null;
                //ThreadPool.QueueUserWorkItem(delegate
                //{
                if (smsQueue.TryDequeue(out result))
                {
                    string[] getStrings = result.Split(new char[] { '&' });
                    if (getStrings.Length.Equals(2))
                    {
                        deviceName = getStrings[0];
                        stateId = getStrings[1];
                        //SendStatusSMS(deviceName, stateId);
                    }
                }
                //});
            };
            smsSendTimer.Enabled = true;
            #endregion sms

            #region sendSmsIfStatusStillInSpecficTime
            System.Timers.Timer timerSmsSend = new System.Timers.Timer();
            //計時器啟動
            timerSmsSend.Elapsed += new ElapsedEventHandler(timerSmsSend_Elapsed);
            //計時器啟動 設定觸發時間
            timerSmsSend.Interval = 60000;
            timerSmsSend.Start();
            #endregion sendSmsIfStatusStillInSpecficTime

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
                        /*
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
                     */    
					} else {
						// Parse SNMP Version 2 TRAP packet 
                        SnmpV3Packet pkt = SnmpV3Packet.DiscoveryRequest();
						pkt.decode(indata, inlen);
						//Console.WriteLine("** SNMP Version 3 TRAP received from {0}:", inep.ToString());
                        if (pkt.Version != SnmpVersion.Ver3)
                        {
							Console.WriteLine("*** NOT an SNMPv3 trap ****");
						} else {
							//Console.WriteLine("*** Community: {0}", pkt.Community.ToString());
                            StringBuilder sb = new StringBuilder();
                            /*
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
                            */
						    string serverityLevel = null, ipAddress = null, eventMessage = null,location=null;
							foreach (Vb v in pkt.Pdu.VbList) {
								//Console.WriteLine("**** {0} {1}: {2}", v.Oid.ToString(), SnmpConstants.GetTypeName(v.Value.Type),v.Value.ToString());
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
                                                //Console.WriteLine(m.Value + " valid");
                                                ipAddress = m.Value;
                                                ipAddress = ip;
                                            }
                                            else
                                            {
                                                //Console.WriteLine("invalid");
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
                            Console.WriteLine("serverityLevel:" + serverityLevel +
                                    Environment.NewLine + "location:" + location + Environment.NewLine +
                                    "eventMessage:" + eventMessage);
                            if(serverityLevel.Equals("0"))
                                SiAuto.Main.LogWarning("serverityLevel:" + serverityLevel +
                                    Environment.NewLine + "location:" + location + Environment.NewLine +
                                    "eventMessage:" + eventMessage);
						    if (smsSB.ToString().Equals(location + "&" +serverityLevel))
						    {
						        //do nothing
						    }
						    else
						    {
                                if (serverityLevel != null && location != null && eventMessage != null)
                                {
                                    
                                    Thread writeCurrentDeviceStatusThread = new System.Threading.Thread
          (delegate()
          {
              //update device
              string DeviceNo = null;
              string SiteCName = null;
              string DeviceCName = null;
              string queryDeviceNo = @"SELECT
public.device_info.device_no,
public.site_info_nbi.site_name,
public.device_base.device_cname
FROM
public.device_info
INNER JOIN public.site_info_nbi ON public.device_info.site_id = public.site_info_nbi.site_id
INNER JOIN public.device_base ON public.device_info.device_id = public.device_base.device_id
WHERE
public.device_info.device_name ='" + location + "'";
              try
              {
                  using (DataTable dt = pgsqSqlClient.get_DataTable(queryDeviceNo))
                  {
                      if (dt != null && dt.Rows.Count != 0)
                      {
                          foreach (DataRow row in dt.Rows)
                          {
                              DeviceNo = row[0].ToString();
                              SiteCName = row[1].ToString();
                              DeviceCName = row[2].ToString();
                          }
                      }
                  }
                  if (DeviceNo != null && !serverityLevel.Equals("7"))
                  {
                      string checkIfDeviceNoExistInStatusTable = @"SELECT
public.device_status_now.device_no
FROM
public.device_status_now
WHERE
public.device_status_now.device_no = " + DeviceNo;
                      using (DataTable dt = pgsqSqlClient.get_DataTable(checkIfDeviceNoExistInStatusTable))
                      {
                          if (dt != null && dt.Rows.Count != 0)
                          {
                              string queryDeviceStatusBySpecificDeviceNo = @"SELECT
public.device_status_now.status_code
FROM
public.device_status_now
WHERE
public.device_status_now.device_no = " + DeviceNo;
                              using (DataTable dt2 = pgsqSqlClient.get_DataTable(queryDeviceStatusBySpecificDeviceNo))
                              {
                                  string stateResult = string.Empty;
                                  if (dt2 != null && dt2.Rows.Count != 0)
                                  {
                                      stateResult = dt2.Rows[0].ItemArray[0]
                                                      .ToString();
                                      string updateSqlScript = null;
                                      if (stateResult.Equals(serverityLevel))
                                      {
                                          //do nothing
                                      }
                                      else
                                      {
                                          //update
                                          updateSqlScript = @"UPDATE device_status_now SET status_code = " + serverityLevel + @" ,message = $$" + eventMessage + @"$$ " + @",update_time=now(),siteAndDeviceName='" + SiteCName + " " + DeviceCName + @"',send_status = 0 WHERE device_no = " + DeviceNo;
                                          pgsqSqlClient.modify(updateSqlScript);
                                          //send sms
                                          //if (serverityLevel.Equals("1") || serverityLevel.Equals("2"))
                                          {
                                              SiAuto.Main.AddCheckpoint("location & serverityLevel", smsSB.ToString());
                                              smsSB.Clear();
                                              smsSB.Insert(0, location + "&" + serverityLevel);
                                              SiAuto.Main.AddCheckpoint("location-serverityLevel-eventMessage", "location:" + location +Environment.NewLine +"serverityLevel:" + serverityLevel + Environment.NewLine +"eventMessage:" + eventMessage);
                                              smsQueue.Enqueue(SiteCName+" "+DeviceCName + "&" + serverityLevel);
                                          }
                                      }
                                  }
                              }

                          }
                          else
                          {
                              //insert
                              string insertSqlScript = @"INSERT INTO device_status_now VALUES (" + DeviceNo + @"," + serverityLevel + @",$$" + eventMessage + "$$" + @",now(),0,'"+SiteCName+" "+DeviceCName+@"')";
                              pgsqSqlClient.modify(insertSqlScript);
                              //send sms
                              //if (serverityLevel.Equals("1") || serverityLevel.Equals("2"))
                              {
                                  SiAuto.Main.AddCheckpoint("location & serverityLevel", smsSB.ToString());
                                  smsSB.Clear();
                                  smsSB.Insert(0, location + "&" + serverityLevel);
                                  SiAuto.Main.AddCheckpoint("location-serverityLevel-eventMessage", "location:" + location + Environment.NewLine + "serverityLevel:" + serverityLevel + Environment.NewLine + "eventMessage:" + eventMessage);
                                  smsQueue.Enqueue(SiteCName + " " + DeviceCName +"&" + serverityLevel);
                              }
                          }
                      }
                      string querySiteID = @"SELECT
public.device_info.site_id
FROM
public.device_info
WHERE
public.device_info.device_no =" + DeviceNo;
                      string siteID = null;
                      using (DataTable dt = pgsqSqlClient.get_DataTable(querySiteID))
                      {
                          if (dt != null && dt.Rows.Count != 0)
                          {
                              foreach (DataRow row in dt.Rows)
                              {
                                  siteID = row[0].ToString();
                              }
                          }
                      }
                      if (siteID != null)
                      {
                          string queryDeviceList = @"SELECT device_no
FROM
device_info
WHERE
site_id=" + siteID;
                          List<int> deviceList = new List<int>();
                          using (DataTable dt = pgsqSqlClient.get_DataTable(queryDeviceList))
                          {
                              if (dt != null && dt.Rows.Count != 0)
                              {
                                  foreach (DataRow row in dt.Rows)
                                  {
                                      deviceList.Add(int.Parse(row[0].ToString()));
                                  }
                              }
                          }
                          List<int> statusList = new List<int>();
                          string queryDeviceStatus = @"SELECT
public.device_status_now.status_code
FROM
public.device_status_now
WHERE
public.device_status_now.device_no = ";
                          for (int i = 0; i < deviceList.Count; i++)
                          {
                              using (DataTable dt = pgsqSqlClient.get_DataTable(queryDeviceStatus + deviceList[i]))
                              {
                                  if (dt != null && dt.Rows.Count != 0)
                                  {
                                      foreach (DataRow row in dt.Rows)
                                      {
                                          statusList.Add(int.Parse(row[0].ToString()));
                                      }
                                  }
                              }
                          }
                          statusList.Sort();
                          string checkIfSiteIDExist = @"SELECT
public.site_status_now_nbi.site_id
FROM
public.site_status_now_nbi
WHERE
public.site_status_now_nbi.site_id = " + siteID;
                          using (DataTable dt = pgsqSqlClient.get_DataTable(checkIfSiteIDExist))
                          {
                              if (dt != null && dt.Rows.Count != 0)
                              {
                              }
                              else
                              {
                                  string insertSiteID = @"INSERT INTO site_status_now_nbi VALUES(" + siteID + @",100)";
                                  pgsqSqlClient.modify(insertSiteID);
                              }
                          }
                          string getWorstStatus = @"SELECT
public.site_status_now_nbi.status_code
FROM
public.site_status_now_nbi
WHERE
public.site_status_now_nbi.site_id = " + siteID ;
                          using (DataTable dt = pgsqSqlClient.get_DataTable(getWorstStatus))
                          {
                              if (dt != null && dt.Rows.Count != 0)
                              {
                                  string updateSiteIDStatus = @"UPDATE site_status_now_nbi SET status_code = " + statusList[0] + @" WHERE site_id=" + siteID + ";";
                                  string updateLinkStatus = @"UPDATE link_status_now_nbi
SET status_code = " + statusList[0] + @" 
WHERE
	bsite_id = " + siteID + ";";
                                  pgsqSqlClient.modify(updateSiteIDStatus + updateLinkStatus);
                              }
                              else
                              {

                              }
                          }
                      }
                  }
              }
              catch (Exception e)
              {

                  Console.WriteLine(e.ToString());
                  SiAuto.Main.LogException(e);
              }
          });
                                    Thread writeToHistoryThread = new System.Threading.Thread
          (delegate()
          {
              string DeviceNo = null;
              string queryDeviceNo = @"SELECT
public.device_info.device_no
FROM
public.device_info
WHERE
public.device_info.device_name = '" + location + "'";
              try
              {
                  using (DataTable dt = pgsqSqlClient.get_DataTable(queryDeviceNo))
                  {
                      if (dt != null && dt.Rows.Count != 0)
                      {
                          foreach (DataRow row in dt.Rows)
                          {
                              DeviceNo = row[0].ToString();
                          }
                      }
                  }
                  string insertSqlScript = null;
                  if (DeviceNo != null)
                  {
                       insertSqlScript = @"INSERT INTO device_status_history_nbi (
	device_no,
	alarm_status,
	message_note
)
VALUES
	(" + DeviceNo + @", " + serverityLevel + @", $$" + eventMessage + "$$)";
                      pgsqSqlClient.modify(insertSqlScript);
                  }
              }
              catch (Exception e)
              {

              }
          });
                                    writeCurrentDeviceStatusThread.Start();
                                    writeToHistoryThread.Start();
                                    writeCurrentDeviceStatusThread.Join();
                                    writeToHistoryThread.Join();
                                }
						    }
						    
						    if (serverityLevel != null && location != null && ipAddress != null && eventMessage != null && false)
						    {
						        if (!File.Exists(Environment.CurrentDirectory + "\\" + DateTime.Now.ToString("yy-MM-dd") + ".csv"))
						        {
                                    using (StreamWriter sw = new StreamWriter(Environment.CurrentDirectory + "\\" + DateTime.Now.ToString("yy-MM-dd") + ".csv", true))
                                    {
                                        var csv = new CsvWriter(sw);
                                        csv.WriteField("serverityLevel");
                                        csv.WriteField("location");
                                        csv.WriteField("ipAddress");
                                        csv.WriteField("eventMessage");
                                        csv.NextRecord();

                                    }
						        }
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
                            //SiAuto.Main.LogStringBuilder("receive trp",sb);
                            //Console.WriteLine("receive trp:"+Environment.NewLine+sb.ToString());
							//Console.WriteLine("** End of SNMP Version 3 TRAP data.");
                            
						}
					}
				} else {
					if (inlen == 0)
						Console.WriteLine("Zero length packet received.");
				}
			}
		}

        private static string smsCheckStillStatusInterval = ConfigurationManager.AppSettings["status_still_time"];
        private static void timerSmsSend_Elapsed(object sender, ElapsedEventArgs e)
        {
            
            string strQuery = @"SELECT msg_nbi_send.phone_number, device_status_now.status_code, device_status_now.site_and_device_name,device_status_now.update_time 
FROM device_status_now INNER JOIN msg_nbi_send ON device_status_now.status_code = msg_nbi_send.message_no 
where device_status_now.send_status = 0 and (now() - device_status_now.update_time) > interval '"+smsCheckStillStatusInterval+@"' = 't'
ORDER BY msg_nbi_send.phone_number, device_status_now.update_time";
            string phoneNumber = null, status = null, deviceName = null;
            StringBuilder smsInsertSqlScriptBuilder = new StringBuilder(0);
            StringBuilder smsHistoryBuilder = new StringBuilder(0);
            try
            {
                using (DataTable dt0 = smsSqlClient.get_DataTable(strQuery))
                {
                    if (dt0 != null && dt0.Rows.Count != 0)
                    {
                        foreach (DataRow row in dt0.Rows)
                        {
                            phoneNumber = row[0].ToString();
                            status = row[1].ToString();
                            deviceName = row[2].ToString();
                            status = getChineseStatusDescript(status);
                            string insertSqlScript = @"INSERT INTO t_sendsms (
	m_sender,
	m_recver,
	m_recvtime,
	m_content,
	m_phoneno,
	m_status
)
VALUES
	(
		'" + m_sender + @"',
		'" + phoneNumber + @"',
		'" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + @"',
		'" + m_sender + @"(UEM)" + deviceName + ":" + status + @"',
		1,
		" + sendSMS + @"
	);";
                            string smsHistory = @"INSERT INTO ams_history (phone_number,message_note) VALUES ('" + phoneNumber + @"','" + m_sender + @"(UEM)" + deviceName + ":" + status + @"');";
                            smsInsertSqlScriptBuilder.AppendLine(insertSqlScript);
                            smsHistoryBuilder.AppendLine(smsHistory);
                        }
                    }
                }
            }
            catch (Exception)
            {
                
                throw;
            }
            string sqlCmd =
                @"update device_status_now set send_status = 1 where send_status = 0 and (now() - update_time) > interval '" + smsCheckStillStatusInterval + @"' = 't'";
            smsSqlClient.modify(sqlCmd);
            if (!smsInsertSqlScriptBuilder.Length.Equals(0))
            {
                smsSqlClient.modify(smsInsertSqlScriptBuilder.ToString());
            }
            if (!smsHistoryBuilder.Length.Equals(0))
            {
                pgsqSqlClient.modify(smsHistoryBuilder.ToString());
            }
        }

        private static string getChineseStatusDescript(string status)
        {
            string queryStateChineseDescription = @"SELECT
public.alarm_set_nbi.cnote
FROM
public.alarm_set_nbi
WHERE
public.alarm_set_nbi.serial_no = " + status;
            try
            {
                using (DataTable dt = pgsqSqlClient.get_DataTable(queryStateChineseDescription))
                {
                    if (dt != null && dt.Rows.Count != 0)
                    {
                        return dt.Rows[0].ItemArray[0].ToString();
                    }
                }
            }
            catch (Exception ex)
            {

                throw ex;
                return null;
            }
            return null;
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

        static void SendStatusSMS(string deviceName, string deviceStateId)
        {
            string queryPhoneNumber = @"SELECT
public.msg_nbi_send.phone_number
FROM
public.msg_nbi_send
WHERE
public.msg_nbi_send.message_no = " + deviceStateId;
            string queryStateChineseDescription = @"SELECT
public.alarm_set_nbi.cnote
FROM
public.alarm_set_nbi
WHERE
public.alarm_set_nbi.serial_no = " + deviceStateId;
            string stateChineseDescription = null;
            string phoneNumber = null;
            StringBuilder smsInsertSqlScriptBuilder = new StringBuilder(0);
            StringBuilder smsHistoryBuilder = new StringBuilder(0);
            try
            {
                using (DataTable dt = pgsqSqlClient.get_DataTable(queryStateChineseDescription))
                {
                    if (dt != null && dt.Rows.Count != 0)
                    {
                        stateChineseDescription = dt.Rows[0].ItemArray[0].ToString();
                    }
                }
            }
            catch (Exception)
            {

                throw;
            }
            if (stateChineseDescription!=null)
            try
            {
                using (DataTable dt = pgsqSqlClient.get_DataTable(queryPhoneNumber))
                {
                    if (dt != null && dt.Rows.Count != 0)
                    {
                        foreach (DataRow row in dt.Rows)
                        {
                            phoneNumber = row[0].ToString();
                            Console.WriteLine(phoneNumber + ":" + deviceName + ":" + stateChineseDescription);
                            //send sms 
                            SiAuto.Main.LogText("send sms", phoneNumber + ":" + deviceName + ":" + stateChineseDescription);
                            string insertSqlScript = @"INSERT INTO t_sendsms (
	m_sender,
	m_recver,
	m_recvtime,
	m_content,
	m_phoneno,
	m_status
)
VALUES
	(
		'" + m_sender + @"',
		'" + phoneNumber + @"',
		'" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + @"',
		'" + m_sender + @"(UEM)" + deviceName + ":" + stateChineseDescription + @"',
		1,
		"+sendSMS+@"
	);";
                            string smsHistory = @"INSERT INTO ams_history (phone_number,message_note) VALUES ('" + phoneNumber + @"','" + m_sender + @"(UEM)" + deviceName + ":" + stateChineseDescription + @"');";
                            smsInsertSqlScriptBuilder.AppendLine(insertSqlScript);
                            smsHistoryBuilder.AppendLine(smsHistory);
                        }
                    }
                }
            }
            catch (Exception)
            {

                throw;
            }
            if (!smsInsertSqlScriptBuilder.Length.Equals(0))
            {
                smsSqlClient.modify(smsInsertSqlScriptBuilder.ToString());
            }
            if (!smsHistoryBuilder.Length.Equals(0))
            {
                pgsqSqlClient.modify(smsHistoryBuilder.ToString());
            }
        }
	}
}