<!-- SPDX-License-Identifier: LGPL-3.0-only -->
<!-- SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev> -->

# @jennifer/mikrotik

A client for the MikroTik RouterOS API, the binary protocol RouterOS serves on
port 8728 (plain TCP) and 8729 (api-ssl). It logs in, runs commands, filters
on the router with query words, and reads streaming commands. The full API is
on the [cheatsheet](cheatsheet.md).

## Conventions

Snippets assume this import:

```jennifer
import "@jennifer/mikrotik/" as mikrotik;
```

The trailing slash resolves to the entry module.

## Connecting

```jennifer
def s as mikrotik.Session init mikrotik.connect(mikrotik.optionsTLS("192.168.88.1", "admin", "secret"));
# ...
mikrotik.close($s);
```

`optionsTLS` dials api-ssl and verifies the router's certificate against the
system roots and the host you dialled, IP or DNS name. RouterOS ships with a
self-signed certificate, so pin it:

```jennifer
def ca as bytes init fs.readBytes("router.pem");
def s as mikrotik.Session init mikrotik.connect(mikrotik.withCA(
    mikrotik.optionsTLS("192.168.88.1", "admin", "secret"), $ca));
```

`insecure(opts)` accepts any certificate. TLS still encrypts, but anyone on
the path can pose as the router; use it only on a wire you trust. `options`
is plain TCP, where the password and every command cross the network in the
clear.

Login sends the name and password (RouterOS 6.43 and later). A router older
than 6.43 answers with a challenge, and the deck completes the MD5
challenge-response on its own.

## Commands

A command is a menu path (`/interface/print`). Attributes are a `map of string
to string`, sent as `=key=value` words; each `!re` reply becomes one row map.
Values are strings, as the API carries them.

```jennifer
for (def iface in mikrotik.print($s, "/interface")) {
    io.printf("%s %s\n", $iface["name"], $iface["running"]);
}

def id as string init mikrotik.run($s, "/ip/address/add", {"address": "10.0.0.1/24", "interface": "ether1"});
```

`run` returns the `=ret=` of the final `!done`, the new item's id for an
`add`. `talk` is the general form and returns the rows.

Query words filter on the router, so only matching rows cross the wire. Each
starts with `?`: `?type=ether` (equals), `?disabled` (present), `?>mtu=1000`
(greater), and `?#!` / `?#&` / `?#|` combine the ones before them.

```jennifer
def ethers as list of map of string to string init
    mikrotik.printWhere($s, "/interface", ["?type=ether", "?running=true"]);
def named as list of map of string to string init
    mikrotik.talkQuery($s, "/interface/print", {".proplist": "name,type"}, ["?type=ether"]);
```

## Streams

Some commands keep pushing replies (`/interface/monitor-traffic`, `/ping`,
`/log/listen`). `listen` starts one with a tag and returns the tag;
`receiveReply` blocks for the next reply carrying it and returns an empty map
once the stream has ended; `cancel` stops it. Replies to other tags on the
same session are skipped.

```jennifer
def tag as string init mikrotik.listen($s, "/interface/monitor-traffic", {"interface": "ether1"});
def reader as task of int init spawn {
    def n as int init 0;
    while (len(mikrotik.receiveReply($s, $tag)) > 0) {
        $n = $n + 1;
    }
    return $n;
};
time.sleep(time.fromSeconds(5));
mikrotik.cancel($s, $tag);
def samples as int init task.wait($reader);
```

The router answers a cancel with a `!trap` of category `2` (interrupted) and a
`!done`; `receiveReply` takes them as the end of the stream. A failure inside
the reader is raised at `task.wait`, so put the `try` there. `talkTagged` adds
a tag to a one-shot command and still reads to its `!done`.

## Errors

A `!trap` (the command failed; the session stays usable) or `!fatal` (the
router closes the connection) throws a `mikrotik.MikrotikError`, kind
`"mikrotik"`, with the `reply`, the trap's `category` and the router's
`routerMessage`. A bad query word or attribute name is the same kind, with
`reply` `""`.

```jennifer
try {
    mikrotik.run($s, "/ip/address/add", {"address": "10.0.0.1/24", "interface": "ether9"});
} catch (e) {
    if ($e.kind == "mikrotik" and $e.reply == "trap") {
        io.printf("refused: %s\n", $e.routerMessage);
    } else {
        throw $e;
    }
}
```

The generic kinds go on: a refused, reset or unreachable connection, a failed
lookup and a certificate that does not verify are `net`'s `net.NetError`
(kind `"net"`); a router silent for 30 seconds is `"timeout"`, one that closes
mid-sentence `"closed"`, and a word over 64 MiB `"limit"`.

## Runtime

Needs `net`, so it runs on the default `jennifer` binary. `jennifer-tiny` has
no network driver.

## Moving from the standard library module

Jennifer has bundled `mikrotik` (`modules/mikrotik.j`) since 0.18.0. The module
is deprecated from 0.26.0 and removed in 0.28.0. This deck has the same types
and functions; only the import changes:

```jennifer
import "mikrotik.j" as mikrotik;              # before
import "@jennifer/mikrotik/" as mikrotik;     # after: jvc add @jennifer/mikrotik
```
