package com.soc.service;

public class FirewallService {

    public boolean blockIp(String ip) {
        String os = System.getProperty("os.name").toLowerCase();
        try {
            if (os.contains("win")) {
                String ruleName = "SOC_BLOCK_" + ip;
                // Xóa rule trùng cũ
                Runtime.getRuntime().exec("cmd.exe /c netsh advfirewall firewall delete rule name=\"" + ruleName + "\"").waitFor();
                // Thêm rule chặn tuyệt đối (All Protocols)
                String cmd = String.format("netsh advfirewall firewall add rule name=\"%s\" dir=in action=block remoteip=%s protocol=any profile=any", ruleName, ip);
                Process p = Runtime.getRuntime().exec("cmd.exe /c " + cmd);
                return p.waitFor() == 0;
            } else {
                Process p = Runtime.getRuntime().exec(new String[]{"sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"});
                return p.waitFor() == 0;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean unblockIp(String ip) {
        String os = System.getProperty("os.name").toLowerCase();
        try {
            if (os.contains("win")) {
                String ruleName = "SOC_BLOCK_" + ip;
                Process p = Runtime.getRuntime().exec("cmd.exe /c netsh advfirewall firewall delete rule name=\"" + ruleName + "\"");
                return p.waitFor() == 0;
            } else {
                Process p = Runtime.getRuntime().exec(new String[]{"sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"});
                return p.waitFor() == 0;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}