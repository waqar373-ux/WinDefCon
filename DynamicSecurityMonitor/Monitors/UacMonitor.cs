using Microsoft.Win32;
using System;

namespace DynamicSecurityMonitor.Monitors
{
    public class UacMonitor
    {
        // Property to hold the status
        public bool IsUacEnabled { get; private set; }

        // Field to track the previous state for notifications
        private bool? wasUacEnabled;

        /// <summary>
        /// Checks the status of User Account Control (UAC) by reading the registry.
        /// This version correctly identifies the insecure "Never notify" setting.
        /// </summary>
        /// <returns>A notification string if UAC was just disabled, otherwise null.</returns>
        public string CheckStatus()
        {
            string notificationMessage = null;
            try
            {
                // Assume UAC is secure until proven otherwise
                IsUacEnabled = true;

                using (RegistryKey uacKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", false))
                {
                    if (uacKey != null)
                    {
                        // The EnableLUA (Limit User Access) registry key is the master switch for UAC.
                        // A value of 1 means it's enabled. A value of 0 means it's truly off.
                        var enableLuaValue = uacKey.GetValue("EnableLUA");
                        if (enableLuaValue == null || (int)enableLuaValue == 0)
                        {
                            IsUacEnabled = false;
                        }

                        // --- THE FIX ---
                        // Check the prompt behavior. If it's 0, it means "Elevate without prompting",
                        // which is the insecure state of "Never Notify".
                        var promptBehaviorValue = uacKey.GetValue("ConsentPromptBehaviorAdmin");
                        if (promptBehaviorValue != null && (int)promptBehaviorValue == 0)
                        {
                            IsUacEnabled = false;
                        }
                    }
                    // If the key doesn't exist, UAC is on by default, so IsUacEnabled remains true.
                }

                // Check if the status has changed from ON to OFF since the last check.
                if (wasUacEnabled == true && !IsUacEnabled)
                {
                    notificationMessage = "User Account Control (UAC) has been set to an insecure level!";
                }

                // Update the previous state for the next check.
                wasUacEnabled = IsUacEnabled;
            }
            catch (Exception ex)
            {
                Console.WriteLine("UAC Check Failed: " + ex.Message);
                IsUacEnabled = false; // Assume insecure on error
            }
            return notificationMessage;
        }
    }
}
