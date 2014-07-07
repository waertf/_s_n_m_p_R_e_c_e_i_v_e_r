using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace checkIfIp4Address
{
    class Program
    {
        static void Main(string[] args)
        {
            while (true)
            {
                string txt = Console.ReadLine();
                string ValidIpAddressRegex = @"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";
                Regex r = new Regex(ValidIpAddressRegex, RegexOptions.IgnoreCase | RegexOptions.Singleline);
   
                Match m = r.Match(txt);
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
