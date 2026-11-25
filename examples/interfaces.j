#!/usr/bin/env -S jennifer run
# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev>
# pragma-jennifer-version: >=0.28.0

/**
 * List a router's interfaces and addresses:
 * jennifer run examples/interfaces.j [host] [user] [password]
 *
 * Logs in over api-ssl (port 8729) and prints every interface and the running
 * ether ports. The defaults are 192.168.88.1, admin and an empty password; the
 * router's certificate must verify (see `withCA` for a self-signed one). Needs
 * a router, so CI only parses it.
 */

use io;
use os;

import "../src/mikrotik.j" as mikrotik;

def host as string init "192.168.88.1";
def user as string init "admin";
def password as string init "";
if (len(os.ARGS) > 1) {
    $host = os.ARGS[1];
}
if (len(os.ARGS) > 2) {
    $user = os.ARGS[2];
}
if (len(os.ARGS) > 3) {
    $password = os.ARGS[3];
}

def s as mikrotik.Session init mikrotik.connect(mikrotik.optionsTLS($host, $user, $password));
defer mikrotik.close($s);

io.printf("interfaces:\n");
for (def iface in mikrotik.print($s, "/interface")) {
    io.printf(
        "  %s|pad=14 %s|pad=10 running=%s\n",
        $iface["name"],
        $iface["type"],
        $iface["running"]);
}

io.printf("\nrunning ether ports:\n");
for (def port in mikrotik.printWhere($s, "/interface", ["?type=ether", "?running=true"])) {
    io.printf("  %s\n", $port["name"]);
}

io.printf("\nip addresses:\n");
for (def addr in mikrotik.print($s, "/ip/address")) {
    io.printf("  %s|pad=20 on %s\n", $addr["address"], $addr["interface"]);
}
