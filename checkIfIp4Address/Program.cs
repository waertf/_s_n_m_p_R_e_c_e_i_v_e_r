using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using CsvHelper;
using CsvHelper.Configuration;
namespace checkIfIp4Address
{
    class Program
    {
        static void Main(string[] args)
        {
            while (true)
            {
                using (StreamWriter sw = new StreamWriter(Environment.CurrentDirectory+"\\"+DateTime.Now.ToString("yy-MM-dd")+".csv",true))
                {
                    var csv = new CsvWriter(sw);
                    csv.WriteField("1");
                    csv.WriteField("2");
                    csv.WriteField("3");
                    csv.NextRecord();
                    
                }
                string ip = Console.ReadLine();
                string ValidIpAddressRegex = @"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";
                Regex r = new Regex(ValidIpAddressRegex, RegexOptions.IgnoreCase | RegexOptions.Singleline);
   
                Match m = r.Match(ip);
                if (m.Success)
                {
                    Console.WriteLine(m.Value+" valid");
                }
                else
                {
                    Console.WriteLine("invalid");
                }
            }
        }
    }
}
