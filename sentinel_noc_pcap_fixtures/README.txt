Sentinel NOC - PCAP test fixtures
==================================

These files are synthetic classic PCAP v2.4 files generated for local IDS pipeline testing.
They contain constructed Ethernet + IPv4 packets only; they do not contain captured traffic
from real people or networks. Timestamps are fixed so offline replay is reproducible.

Files
-----
1. normal.pcap
   20 mixed TCP/UDP packets; a small set of destination ports. Intended as a baseline.

2. port_scan.pcap
   25 TCP SYN packets from 192.168.1.50 to 25 unique destination ports within 2.5 seconds.
   Intended to exercise Port Scan Heuristic.

3. syn_rate.pcap
   120 bare TCP SYN packets from 192.168.1.60 within about 1.2 seconds.
   Intended to exercise Bare-SYN Rate Heuristic.

4. icmp_threshold.pcap
   120 IPv4 ICMP echo requests from 192.168.1.70 within about 1.2 seconds.
   Intended to exercise ICMP Threshold.

How to use
----------
1. Run the app from the project root: mvn javafx:run
2. In Offline PCAP import, click Select File and select one fixture.
3. Keep the time window at 10 seconds initially.
4. For port_scan.pcap, set the port-scan threshold to a value below the observed
   number of unique destination ports (for example 15).
5. For syn_rate.pcap, set the SYN threshold to a value below 120 (for example 100).
6. For icmp_threshold.pcap, set the ICMP threshold to a value below 120 (for example 100).
7. Click Start Import and inspect Recent Alerts and Traffic Sample.
8. Repeat with normal.pcap as a baseline.

Important
---------
- Expected alert behavior depends on the exact threshold comparison and rule implementation.
  Check PCAP_PIPELINE.md or the detection-rule code if a boundary result differs.
- The fixtures are separate imports. If the app retains prior session alerts, clear/restart
  the app between tests when you need an isolated alert count.
- These fixtures test the offline pipeline, not live capture.
- PCAPNG is not supported by the current app; these files are classic PCAP.
