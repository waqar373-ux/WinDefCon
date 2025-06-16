using System;
using NetFwTypeLib;

namespace DynamicSecurityMonitor.Monitors
{
    public class FirewallMonitor
    {
        // Store previous state to detect changes
        private bool? wasDomainFirewallOn;
        private bool? wasPrivateFirewallOn;
        private bool? wasPublicFirewallOn;

        public bool IsDomainFirewallOn { get; private set; }
        public bool IsPrivateFirewallOn { get; private set; }
        public bool IsPublicFirewallOn { get; private set; }

        /// <summary>
        /// Checks the current status of all firewall profiles.
        /// </summary>
        /// <returns>A string message if the state has changed to insecure, otherwise null.</returns>
        public string CheckStatus()
        {
            string notificationMessage = null;
            try
            {
                INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));

                IsDomainFirewallOn = fwPolicy2.get_FirewallEnabled((NET_FW_PROFILE_TYPE2_)1); // 1 = Domain
                IsPrivateFirewallOn = fwPolicy2.get_FirewallEnabled((NET_FW_PROFILE_TYPE2_)2); // 2 = Private
                IsPublicFirewallOn = fwPolicy2.get_FirewallEnabled((NET_FW_PROFILE_TYPE2_)4); // 4 = Public

                // Check if any firewall has been turned OFF since the last check
                if ((wasDomainFirewallOn == true && !IsDomainFirewallOn) ||
                    (wasPrivateFirewallOn == true && !IsPrivateFirewallOn) ||
                    (wasPublicFirewallOn == true && !IsPublicFirewallOn))
                {
                    notificationMessage = "A firewall profile has been disabled!";
                }

                // Update previous state for the next check
                wasDomainFirewallOn = IsDomainFirewallOn;
                wasPrivateFirewallOn = IsPrivateFirewallOn;
                wasPublicFirewallOn = IsPublicFirewallOn;
            }
            catch (Exception)
            {
                // Error occurred, state is uncertain
            }
            return notificationMessage;
        }

        /// <summary>
        /// Enables all firewall profiles. Requires administrator privileges.
        /// </summary>
        public bool EnableFirewalls()
        {
            try
            {
                INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
                fwPolicy2.set_FirewallEnabled((NET_FW_PROFILE_TYPE2_)1, true); // Domain
                fwPolicy2.set_FirewallEnabled((NET_FW_PROFILE_TYPE2_)2, true); // Private
                fwPolicy2.set_FirewallEnabled((NET_FW_PROFILE_TYPE2_)4, true); // Public
                CheckStatus(); // Re-check status immediately after enabling
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
