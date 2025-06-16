using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;

namespace DynamicSecurityMonitor.Monitors
{
    // A detailed class to hold information about each startup item found.
    public class StartupItem
    {
        public string Name { get; set; }
        public string Command { get; set; }
        public string Location { get; set; }

        // --- Properties to help with disabling the item ---
        public string RegistryPath { get; set; } // e.g., SOFTWARE\Microsoft\Windows\CurrentVersion\Run
        public RegistryHive Hive { get; set; } // e.g., HKEY_CURRENT_USER or HKEY_LOCAL_MACHINE
        public bool IsFolderItem => !string.IsNullOrEmpty(Command) && (Location.Contains("Folder"));
    }

    public class StartupProgramMonitor
    {
        public List<StartupItem> ScanForStartupPrograms()
        {
            var startupItems = new List<StartupItem>();

            string[] registryKeys = {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
            };

            // Scan HKEY_CURRENT_USER
            ScanRegistryHive(startupItems, Registry.CurrentUser, "HKCU", registryKeys);
            // Scan HKEY_LOCAL_MACHINE
            ScanRegistryHive(startupItems, Registry.LocalMachine, "HKLM", registryKeys);

            // Scan Startup Folders
            ScanStartupFolder(startupItems, Environment.SpecialFolder.Startup, "Current User Startup Folder");
            ScanStartupFolder(startupItems, Environment.SpecialFolder.CommonStartup, "All Users Startup Folder");

            return startupItems;
        }

        // Helper method to scan a specific part of the registry
        private void ScanRegistryHive(List<StartupItem> items, RegistryKey hive, string hiveName, string[] keyPaths)
        {
            foreach (string keyPath in keyPaths)
            {
                // Use a try-catch block for security exceptions when accessing HKLM
                try
                {
                    using (RegistryKey key = hive.OpenSubKey(keyPath))
                    {
                        if (key != null)
                        {
                            foreach (string valueName in key.GetValueNames())
                            {
                                items.Add(new StartupItem
                                {
                                    Name = valueName,
                                    Command = key.GetValue(valueName).ToString(),
                                    Location = hiveName + "\\" + keyPath,
                                    Hive = (hive == Registry.CurrentUser) ? RegistryHive.CurrentUser : RegistryHive.LocalMachine,
                                    RegistryPath = keyPath
                                });
                            }
                        }
                    }
                }
                catch (System.Security.SecurityException)
                {
                    // Ignore keys we don't have permission to read
                    continue;
                }
            }
        }

        // Helper method to scan a specific startup folder
        private void ScanStartupFolder(List<StartupItem> items, Environment.SpecialFolder folder, string locationName)
        {
            string folderPath = Environment.GetFolderPath(folder);
            if (Directory.Exists(folderPath))
            {
                foreach (string filePath in Directory.GetFiles(folderPath))
                {
                    items.Add(new StartupItem
                    {
                        Name = Path.GetFileName(filePath),
                        Command = filePath,
                        Location = locationName
                    });
                }
            }
        }

        /// <summary>
        /// Disables a startup item by either deleting its registry key or its file.
        /// </summary>
        /// <param name="itemToDisable">The StartupItem object to be disabled.</param>
        /// <returns>True if successful, otherwise false.</returns>
        public bool DisableStartupItem(StartupItem itemToDisable)
        {
            try
            {
                if (itemToDisable.IsFolderItem)
                {
                    // If it's a file in a startup folder, delete the file.
                    if (File.Exists(itemToDisable.Command))
                    {
                        File.Delete(itemToDisable.Command);
                        return true;
                    }
                }
                else
                {
                    // If it's a registry item, open the correct key and delete the value.
                    RegistryKey hive = (itemToDisable.Hive == RegistryHive.CurrentUser) ? Registry.CurrentUser : Registry.LocalMachine;
                    using (RegistryKey key = hive.OpenSubKey(itemToDisable.RegistryPath, true)) // true for writable
                    {
                        if (key != null)
                        {
                            key.DeleteValue(itemToDisable.Name);
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to disable startup item '{itemToDisable.Name}': {ex.Message}");
                return false;
            }
            return false;
        }
    }
}
