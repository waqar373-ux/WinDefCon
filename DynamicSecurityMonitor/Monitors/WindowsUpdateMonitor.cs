using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using WUApiLib;
using System.Management; // Added for more detailed hotfix info

namespace DynamicSecurityMonitor.Monitors
{
    // A class to hold all the rich information from systeminfo
    public class SystemInformation
    {
        public string OsName { get; set; } = "Loading...";
        public string OsVersion { get; set; } = "Loading...";
        public List<string> Hotfixes { get; set; } = new List<string>();
        public int HotfixCount => Hotfixes.Count;
        public DateTime? LastHotfixDate { get; set; } // NEW: Date of the last installed update
    }

    public class WindowsUpdateMonitor
    {
        /// <summary>
        /// Asynchronously gets detailed system information including the date of the last installed hotfix.
        /// </summary>
        public async Task<SystemInformation> GetSystemInfoAsync()
        {
            var sysInfo = new SystemInformation();

            try
            {
                // This part remains the same to get OS Name and Version quickly
                string output = await Task.Run(() =>
                {
                    ProcessStartInfo psi = new ProcessStartInfo("systeminfo.exe")
                    {
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    };
                    using (Process p = Process.Start(psi)) { return p.StandardOutput.ReadToEnd(); }
                });
                sysInfo.OsName = Regex.Match(output, @"^OS Name:\s*(.*)", RegexOptions.Multiline).Groups[1].Value.Trim();
                sysInfo.OsVersion = Regex.Match(output, @"^OS Version:\s*(.*)", RegexOptions.Multiline).Groups[1].Value.Trim();

                // --- NEW, MORE RELIABLE LOGIC FOR HOTFIX DATES ---
                // We will use WMI (Win32_QuickFixEngineering) as it directly provides install dates.
                await Task.Run(() =>
                {
                    ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_QuickFixEngineering");
                    ManagementObjectCollection collection = searcher.Get();
                    DateTime mostRecent = DateTime.MinValue;

                    foreach (ManagementObject qfe in collection)
                    {
                        // Add the hotfix ID to our list
                        sysInfo.Hotfixes.Add(qfe["HotFixID"]?.ToString());

                        // Parse the "InstalledOn" date and find the latest one
                        string installedOnStr = qfe["InstalledOn"]?.ToString();
                        if (!string.IsNullOrEmpty(installedOnStr) && DateTime.TryParseExact(installedOnStr, "M/d/yyyy", CultureInfo.InvariantCulture, DateTimeStyles.None, out DateTime installedDate))
                        {
                            if (installedDate > mostRecent)
                            {
                                mostRecent = installedDate;
                            }
                        }
                    }
                    if (mostRecent != DateTime.MinValue)
                    {
                        sysInfo.LastHotfixDate = mostRecent;
                    }
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine("Failed to get SystemInfo: " + ex.Message);
                sysInfo.OsName = "Error retrieving system info.";
            }
            return sysInfo;
        }

        // (The rest of the class, CheckForNewUpdatesAsync and OpenUpdateSettings, remains exactly the same)
        public async Task<int> CheckForNewUpdatesAsync()
        {
            try
            {
                UpdateSession updateSession = new UpdateSession();
                IUpdateSearcher updateSearcher = updateSession.CreateUpdateSearcher();
                ISearchResult searchResult = await Task.Run(() => updateSearcher.Search("IsInstalled=0 and IsHidden=0"));
                return searchResult.Updates.Count;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Failed to check for updates: " + ex.Message);
                return -1;
            }
        }

        public void OpenUpdateSettings()
        {
            try
            {
                Process.Start("ms-settings:windowsupdate");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Failed to open update settings: " + ex.Message);
                try { Process.Start("control.exe", "/name Microsoft.WindowsUpdate"); } catch { }
            }
        }
    }
}
