package com.soc.model;

public record TcpFlags(boolean syn, boolean ack, boolean fin, boolean rst, boolean psh, boolean urg) {
    @Override
    public String toString() {
        StringBuilder flags = new StringBuilder();
        append(flags, "SYN", syn);
        append(flags, "ACK", ack);
        append(flags, "FIN", fin);
        append(flags, "RST", rst);
        append(flags, "PSH", psh);
        append(flags, "URG", urg);
        return flags.length() == 0 ? "-" : flags.toString();
    }

    private static void append(StringBuilder flags, String name, boolean present) {
        if (present) {
            if (!flags.isEmpty()) {
                flags.append(' ');
            }
            flags.append(name);
        }
    }
}
