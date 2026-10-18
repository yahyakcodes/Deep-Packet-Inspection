package com.packetanalyzer.dpi;

import java.util.ArrayList;
import java.util.List;

/**
 * Command-line entry point for the multi-threaded DPI engine.
 * {@code main()}
 * <pre>
 * Usage: dpi-engine &lt;input.pcap&gt; &lt;output.pcap&gt; [options]
 * Options:
 *   --block-ip &lt;ip&gt;        Block source IP
 *   --block-app &lt;app&gt;      Block application (YouTube, Facebook, etc.)
 *   --block-domain &lt;dom&gt;   Block domain (substring match)
 *   --lbs &lt;n&gt;              Number of load balancer threads (default: 2)
 *   --fps &lt;n&gt;              FP threads per LB (default: 2)
 * </pre>
 */
public final class DpiEngineApp {

    private DpiEngineApp() {
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            printUsage();
            System.exit(1);
        }

        String input = args[0];
        String output = args[1];

        DpiEngine.Config config = new DpiEngine.Config();
        List<String> blockIps = new ArrayList<>();
        List<String> blockApps = new ArrayList<>();
        List<String> blockDomains = new ArrayList<>();

        for (int i = 2; i < args.length; i++) {
            String arg = args[i];
            if (arg.equals("--block-ip") && i + 1 < args.length) {
                blockIps.add(args[++i]);
            } else if (arg.equals("--block-app") && i + 1 < args.length) {
                blockApps.add(args[++i]);
            } else if (arg.equals("--block-domain") && i + 1 < args.length) {
                blockDomains.add(args[++i]);
            } else if (arg.equals("--lbs") && i + 1 < args.length) {
                config.setNumLbs(Integer.parseInt(args[++i]));
            } else if (arg.equals("--fps") && i + 1 < args.length) {
                config.setFpsPerLb(Integer.parseInt(args[++i]));
            }
        }

        DpiEngine engine = new DpiEngine(config);

        for (String ip : blockIps) {
            engine.blockIp(ip);
        }
        for (String app : blockApps) {
            engine.blockApp(app);
        }
        for (String domain : blockDomains) {
            engine.blockDomain(domain);
        }

        if (!engine.process(input, output)) {
            System.exit(1);
        }

        System.out.println();
        System.out.println("Output written to: " + output);
    }

    private static void printUsage() {
        System.out.println();
        System.out.println("DPI Engine v2.0 - Multi-threaded Deep Packet Inspection");
        System.out.println("========================================================");
        System.out.println();
        System.out.println("Usage: dpi-engine <input.pcap> <output.pcap> [options]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --block-ip <ip>        Block source IP");
        System.out.println("  --block-app <app>      Block application (YouTube, Facebook, etc.)");
        System.out.println("  --block-domain <dom>   Block domain (substring match)");
        System.out.println("  --lbs <n>              Number of load balancer threads (default: 2)");
        System.out.println("  --fps <n>              FP threads per LB (default: 2)");
        System.out.println();
        System.out.println("Example:");
        System.out.println("  dpi-engine capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50");
    }
}
