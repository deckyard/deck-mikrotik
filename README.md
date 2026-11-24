# @jennifer/mikrotik

[![test](https://github.com/jennifer-language/deck-mikrotik/actions/workflows/test.yml/badge.svg)](https://github.com/jennifer-language/deck-mikrotik/actions/workflows/test.yml)
[![Documentation](https://img.shields.io/badge/docs-github%20pages-blue)](https://jennifer-language.github.io/deck-mikrotik/)
[![release](https://img.shields.io/github/v/release/jennifer-language/deck-mikrotik)](https://github.com/jennifer-language/deck-mikrotik/releases/latest)

A [Jennifer](https://jennifer-lang.dev/) deck that talks to MikroTik™ routers
over the RouterOS™ API (port 8728, or api-ssl on 8729): log in, run commands,
filter on the router with query words, and read streaming commands such as
`/interface/monitor-traffic`.

It was Jennifer's bundled `mikrotik.j` module until 0.27; the surface is the
same, so moving over changes only the import:

```jennifer
import "@jennifer/mikrotik/" as mikrotik;   # was: import "mikrotik.j" as mikrotik;
```

**[Documentation](https://jennifer-language.github.io/deck-mikrotik/)**

## Install

```sh
jvc add @jennifer/mikrotik
```

This vendors the deck to `vendor/<scope>/mikrotik/`. Without `jvc`, unpack the
`src/` subtree of a release archive (`<scope>-mikrotik-<version>.tar.gz`) there.

## Usage

```jennifer
import "@jennifer/mikrotik/" as mikrotik;

def s as mikrotik.Session init mikrotik.connect(mikrotik.optionsTLS("192.168.88.1", "admin", "secret"));
for (def iface in mikrotik.print($s, "/interface")) {
    io.printf("%s %s\n", $iface["name"], $iface["running"]);
}
mikrotik.close($s);
```

## Requirements

Jennifer 0.27.0 or newer, the default `jennifer` binary (`net`), not
`jennifer-tiny`, and a router with the `api` or `api-ssl` service enabled.

## Development

```sh
tools/check-all.sh                   # the full gate, as CI runs it
jennifer test src/mikrotik_test.j    # the test overlay
tools/check-docs.sh                  # docs against the code
tools/pack.sh dist                   # build the release archive
```

## Licence

LGPL-3.0-only, see [LICENSE](LICENSE). Copyright (C) 2026 mplx &lt;mplx@jennifer-lang.dev&gt;.

`tools/check-headers.sh` checks every source file's SPDX header against
`deck.toml`.

## Trademarks

MikroTik™ and RouterOS™ are trademarks of SIA "Mikrotīkls". Other product and
company names may be trademarks of their respective owners. They are used only
to identify the products this deck works with. This deck is an independent
project, not affiliated with, sponsored or endorsed by SIA Mikrotikls.
