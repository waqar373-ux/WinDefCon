using System;
using System.Diagnostics;
using System.IO;

namespace DynamicSecurityMonitor.Monitors
{
    public class DepMonitor
    {
        public string DepStatus { get; private set; } = "Unknown";

        public void CheckStatus()
        {
            try
            {
                string systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
                string cmdPath = Path.Combine(systemRoot, "Sysnative", "cmd.exe");

                // If Sysnative doesn't exist, fallback to System32
                if (!File.Exists(cmdPath))
                {
                    cmdPath = Path.Combine(systemRoot, "System32", "cmd.exe");
                }

                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = cmdPath,
                    Arguments = "/c bcdedit /enum {current}",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (Process process = Process.Start(psi))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    foreach (string line in output.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries))
                    {
                        string trimmed = line.Trim();

                        if (trimmed.StartsWith("nx", StringComparison.OrdinalIgnoreCase))
                        {
                            string value = trimmed.Substring(2).Trim();

                            if (value.Equals("OptIn", StringComparison.OrdinalIgnoreCase))
                                DepStatus = "DEP is On (OptIn: Only essential programs)";
                            else if (value.Equals("OptOut", StringComparison.OrdinalIgnoreCase))
                                DepStatus = "DEP is On (OptOut: All programs)";
                            else if (value.Equals("AlwaysOn", StringComparison.OrdinalIgnoreCase))
                                DepStatus = "DEP is Always On";
                            else if (value.Equals("AlwaysOff", StringComparison.OrdinalIgnoreCase))
                                DepStatus = "DEP is Off (Insecure)";
                            else
                                DepStatus = "DEP: Unknown setting → " + value;

                            return; // Stop after finding DEP line
                        }
                    }

                    DepStatus = "DEP setting not found in BCDEdit output.";
                }
            }
            catch (Exception ex)
            {
                DepStatus = "Error: " + ex.Message;
            }
        }
    }
}
