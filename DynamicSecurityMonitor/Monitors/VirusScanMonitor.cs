using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace DynamicSecurityMonitor.Monitors
{
    public class VirusScanMonitor
    {
        /// <summary>
        /// Asynchronously starts a Windows Defender quick scan using its command-line tool.
        /// </summary>
        /// <returns>True if the scan process started successfully, otherwise false.</returns>
        public async Task<bool> StartQuickScanAsync()
        {
            // Find the most up-to-date path for the Windows Defender command-line tool.
            string mpCmdRunPath = GetDefenderPath();

            if (string.IsNullOrEmpty(mpCmdRunPath))
            {
                Console.WriteLine("Could not find Windows Defender executable (MpCmdRun.exe).");
                return false;
            }

            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = mpCmdRunPath;
                // -Scan -ScanType 1 initiates a Quick Scan.
                psi.Arguments = "-Scan -ScanType 1";
                psi.CreateNoWindow = true;
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                psi.Verb = "runas"; // Must run as administrator.

                using (Process process = new Process { StartInfo = psi })
                {
                    process.Start();
                    // Asynchronously wait for the process to finish.
                    await Task.Run(() => process.WaitForExit());
                }
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to start virus scan: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// NEW: Intelligently finds the path to MpCmdRun.exe by checking modern and legacy locations.
        /// </summary>
        /// <returns>The full path to the executable, or null if not found.</returns>
        private string GetDefenderPath()
        {
            // The modern path is in ProgramData, inside a versioned folder.
            string modernPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows Defender\Platform");
            if (Directory.Exists(modernPath))
            {
                // Get the latest version directory (e.g., 4.18.2205.7-0)
                var latestVersionDir = new DirectoryInfo(modernPath)
                    .GetDirectories()
                    .OrderByDescending(d => d.Name)
                    .FirstOrDefault();

                if (latestVersionDir != null)
                {
                    string potentialPath = Path.Combine(latestVersionDir.FullName, "MpCmdRun.exe");
                    if (File.Exists(potentialPath))
                    {
                        Console.WriteLine("Found Defender at modern path: " + potentialPath);
                        return potentialPath;
                    }
                }
            }

            // If not found, check the legacy Program Files path.
            string legacyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
            if (File.Exists(legacyPath))
            {
                Console.WriteLine("Found Defender at legacy path: " + legacyPath);
                return legacyPath;
            }

            // Return null if not found in any known location.
            return null;
        }
    }
}
