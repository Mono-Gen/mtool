using System;
using MMulticastTool;

namespace MToolTests
{
    /// <summary>
    /// Simple test runner for MToolCore logic.
    /// Does not require Npcap or active network.
    /// </summary>
    class Program
    {
        static int total = 0;
        static int passed = 0;

        static void Main(string[] args)
        {
            Console.WriteLine("========================================");
            Console.WriteLine("       MTool Unit Test Runner           ");
            Console.WriteLine("========================================\n");

            // --- Test: IsMulticast ---
            Console.WriteLine("[Section: Multicast Validation]");
            Assert("239.1.1.1 is Multicast", MToolCore.IsMulticast("239.1.1.1") == true);
            Assert("224.0.0.1 is Multicast", MToolCore.IsMulticast("224.0.0.1") == true);
            Assert("239.255.255.255 is Multicast", MToolCore.IsMulticast("239.255.255.255") == true);
            Assert("192.168.1.1 is NOT Multicast", MToolCore.IsMulticast("192.168.1.1") == false);
            Assert("8.8.8.8 is NOT Multicast", MToolCore.IsMulticast("8.8.8.8") == false);
            Assert("Invalid string is NOT Multicast", MToolCore.IsMulticast("not-an-ip") == false);
            Assert("Empty string is NOT Multicast", MToolCore.IsMulticast("") == false);
            Console.WriteLine();

            // --- Test: CalculateIntervalMs ---
            Console.WriteLine("[Section: Interval Calculation]");
            // 1Mbps, 125 bytes (1000 bits) -> 1000 packets per sec -> 1.0ms interval
            double i1 = MToolCore.CalculateIntervalMs(1.0, 125, 1000);
            Assert("1Mbps, 125B = 1.0ms", Math.Abs(i1 - 1.0) < 0.001);

            // 10Mbps, 1250 bytes (10000 bits) -> 1000 packets per sec -> 1.0ms interval
            double i2 = MToolCore.CalculateIntervalMs(10.0, 1250, 1000);
            Assert("10Mbps, 1250B = 1.0ms", Math.Abs(i2 - 1.0) < 0.001);

            // 0.5Mbps (500kbps), 125 bytes (1000 bits) -> 500 packets per sec -> 2.0ms interval
            double i3 = MToolCore.CalculateIntervalMs(0.5, 125, 1000);
            Assert("0.5Mbps, 125B = 2.0ms", Math.Abs(i3 - 2.0) < 0.001);

            // 0Mbps should fallback to default
            double i4 = MToolCore.CalculateIntervalMs(0.0, 64, 500);
            Assert("0Mbps returns fallback (500ms)", i4 == 500.0);
            Console.WriteLine();

            // --- Summary ---
            Console.WriteLine("========================================");
            if (passed == total)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine(" ALL TESTS PASSED ({0}/{1})", passed, total);
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(" SOME TESTS FAILED ({0}/{1})", passed, total);
            }
            Console.ResetColor();
            Console.WriteLine("========================================");

            if (passed < total) Environment.Exit(1);
        }

        static void Assert(string name, bool condition)
        {
            total++;
            if (condition)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("  [PASS] ");
                passed++;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write("  [FAIL] ");
            }
            Console.ResetColor();
            Console.WriteLine(name);
        }
    }
}
