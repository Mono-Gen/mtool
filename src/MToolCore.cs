using System;
using System.Net;

namespace MMulticastTool
{
    /// <summary>
    /// Core logic and calculations for MTool.
    /// Extracted for modularity and unit testing.
    /// </summary>
    public static class MToolCore
    {
        public const string SIG = "MTOOL";
        public const int HEADER_SIZE = 21;
        
        // Network header sizes (Ethernet 14 + IPv4 20 + UDP 8 = 42 bytes)
        public const int ETHERNET_HEADER_SIZE = 14;
        public const int IPV4_HEADER_SIZE = 20;
        public const int UDP_HEADER_SIZE = 8;
        public const int TOTAL_NETWORK_HEADERS = ETHERNET_HEADER_SIZE + IPV4_HEADER_SIZE + UDP_HEADER_SIZE;
        /// <summary>
        /// Calculates the required packet interval in milliseconds based on target bandwidth.
        /// </summary>
        /// <param name="bandwidthMbps">Target bandwidth in Mbps.</param>
        /// <param name="packetSize">Size of the packet in bytes (UDP payload).</param>
        /// <param name="fallbackInterval">Default interval if bandwidth is not specified.</param>
        /// <returns>Interval in milliseconds.</returns>
        public static double CalculateIntervalMs(double bandwidthMbps, int packetSize, int fallbackInterval)
        {
            if (bandwidthMbps <= 0) return (double)fallbackInterval;
            
            // bandwidthMbps * 1,000,000 = bits per second
            // packetSize * 8 = bits per packet
            // bits per second / bits per packet = packets per second
            // 1000 / packets per second = interval in ms
            double bitsPerSec = bandwidthMbps * 1000000.0;
            double bitsPerPacket = packetSize * 8.0;
            
            if (bitsPerPacket <= 0) return (double)fallbackInterval;
            
            double packetsPerSec = bitsPerSec / bitsPerPacket;
            return 1000.0 / packetsPerSec;
        }

        /// <summary>
        /// Validates if a string is a valid IPv4 multicast address (224.0.0.0 - 239.255.255.255).
        /// </summary>
        /// <param name="ip">IP address string to validate.</param>
        /// <returns>True if it is a valid multicast address.</returns>
        public static bool IsMulticast(string ip)
        {
            if (string.IsNullOrEmpty(ip)) return false;
            try
            {
                IPAddress addr;
                if (!IPAddress.TryParse(ip, out addr)) return false;
                
                byte[] b = addr.GetAddressBytes();
                if (b.Length != 4) return false;
                
                // Multicast range is 224.0.0.0 to 239.255.255.255 (Class D)
                return b[0] >= 224 && b[0] <= 239;
            }
            catch
            {
                return false;
            }
        }
    }
}
