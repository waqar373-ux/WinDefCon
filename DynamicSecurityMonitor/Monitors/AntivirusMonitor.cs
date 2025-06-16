using System;
using System.Management;

namespace DynamicSecurityMonitor.Monitors
{
    public class AntivirusMonitor
    {
        private bool? wasAvActive;
        public bool IsAvActive { get; private set; }

        /// <summary>
        /// Checks if any installed antivirus product is active and running.
        /// </summary>
        /// <returns>A string message if the state has changed to insecure, otherwise null.</returns>
        public string CheckStatus()
        {
            string notificationMessage = null;
            IsAvActive = false; // Assume inactive until a valid, active AV is found
            try
            {
                string wmiPath = @"\\" + Environment.MachineName + @"\root\SecurityCenter2";
                string wmiQuery = "SELECT * FROM AntiVirusProduct";
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmiPath, wmiQuery);
                ManagementObjectCollection avCollection = searcher.Get();

                foreach (ManagementObject av in avCollection)
                {
                    // productState is a bitmask. The third hex value indicates its status.
                    // 0x10 means enabled. 0x11 means enabled and up to date.
                    uint productState = (uint)av["productState"];
                    if ((productState & 0x0000FF00) >> 8 == 0x11 || (productState & 0x0000FF00) >> 8 == 0x10)
                    {
                        IsAvActive = true;
                        break; // Found an active AV, no need to check others
                    }
                }

                // If the state has changed from active to inactive, prepare a notification
                if (wasAvActive == true && !IsAvActive)
                {
                    notificationMessage = "Antivirus software has been disabled or is malfunctioning.";
                }

                wasAvActive = IsAvActive; // Update state for next check
            }
            catch (Exception)
            {
                // WMI can fail if the service is stopped, etc.
            }
            return notificationMessage;
        }
    }
}
