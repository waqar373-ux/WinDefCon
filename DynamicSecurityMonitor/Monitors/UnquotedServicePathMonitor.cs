using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Management;

namespace DynamicSecurityMonitor.Monitors
{
    public class UnquotedServicePathMonitor
    {
        /// <summary>
        /// Scans all Windows services and returns a list of services with vulnerable unquoted paths.
        /// </summary>
        /// <returns>A list of vulnerability messages (ServiceName: Path).</returns>
        public List<string> ScanForVulnerableServices()
        {
            var vulnerableServices = new List<string>();

            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Service");
                foreach (ManagementObject service in searcher.Get())
                {
                    string serviceName = service["Name"]?.ToString() ?? "(Unknown)";
                    string pathName = service["PathName"]?.ToString();

                    if (string.IsNullOrWhiteSpace(pathName))
                        continue;

                    if (pathName.Contains(" ") && !pathName.StartsWith("\""))
                    {
                        int exeIndex = pathName.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
                        if (exeIndex == -1)
                            continue;

                        string exePath = pathName.Substring(0, exeIndex + 4);

                        if (exePath.Contains(" "))
                        {
                            vulnerableServices.Add($"{serviceName}:{pathName}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                vulnerableServices.Add("ERROR: Could not scan services - " + ex.Message);
            }

            return vulnerableServices;
        }

        /// <summary>
        /// NEW: Fixes a vulnerable service by adding quotes around its path in the registry.
        /// </summary>
        /// <param name="serviceName">The name of the service to fix.</param>
        /// <returns>True if successful, otherwise false.</returns>
        public bool FixService(string serviceName)
        {
            try
            {
                // The configuration for services is stored in the registry.
                // We need to open the specific key for the service we want to modify.
                // This operation requires administrator privileges.
                string registryPath = $@"SYSTEM\CurrentControlSet\Services\{serviceName}";
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(registryPath, true))
                {
                    if (key == null)
                    {
                        return false; // Key not found
                    }

                    // Get the current path from the 'ImagePath' value.
                    object imagePathObj = key.GetValue("ImagePath");
                    if (imagePathObj == null)
                    {
                        return false; // ImagePath value doesn't exist
                    }

                    string currentPath = imagePathObj.ToString();

                    // Add quotes around the entire path.
                    string newPath = $"\"{currentPath}\"";

                    // Write the new, quoted path back to the registry.
                    key.SetValue("ImagePath", newPath);
                }
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to fix service '{serviceName}': {ex.Message}");
                return false;
            }
        }
    }
}
