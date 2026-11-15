#!/usr/bin/env -S jennifer run
# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev>
# pragma-jennifer-version: >=0.26.0

/**
 * Watch an interface's traffic for five samples:
 * jennifer run examples/monitor.j host user password [interface]
 *
 * Starts `/interface/monitor-traffic` as a tagged stream, reads the pushed
 * replies with `receiveReply`, then stops it with `cancel` and drains the
 * stream to its end. Needs a router, so CI only parses it.
 */

use io;
use os;

import "../src/mikrotik.j" as mikrotik;

if (len(os.ARGS) < 4) {
    io.printf("usage: monitor.j host user password [interface]\n");
    exit 2;
}
def iface as string init "ether1";
if (len(os.ARGS) > 4) {
    $iface = os.ARGS[4];
}

def s as mikrotik.Session init mikrotik.connect(mikrotik.optionsTLS(
    os.ARGS[1],
    os.ARGS[2],
    os.ARGS[3]));
defer mikrotik.close($s);

def tag as string init mikrotik.listen($s, "/interface/monitor-traffic", {"interface": $iface});
for (def i in 0..5) {
    def sample as map of string to string init mikrotik.receiveReply($s, $tag);
    io.printf(
        "rx %s bit/s, tx %s bit/s\n",
        $sample["rx-bits-per-second"],
        $sample["tx-bits-per-second"]);
}
mikrotik.cancel($s, $tag);
# the stream ends with an empty map once the router confirms the cancel
while (len(mikrotik.receiveReply($s, $tag)) > 0) {
}
