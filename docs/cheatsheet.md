<!-- SPDX-License-Identifier: LGPL-3.0-only -->
<!-- SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev> -->

# mikrotik cheatsheet

Every export of `@deckyard/mikrotik`. Background is in
[the introduction](index.md).

```jennifer
import "@deckyard/mikrotik/" as mikrotik;
```

A `!trap` or `!fatal` reply, a bad query word or attribute name, and a
plain-TCP login without `allowInsecureAuth` throw a `MikrotikError` (kind
`"mikrotik"`). A socket failure is `net`'s `net.NetError` (kind `"net"`); a
deadline, a router closing mid-sentence and a reply over a cap (a word over 64
MiB, a sentence over 4096 words, a reply over 262144 words or 64 MiB) are
kinds `"timeout"`, `"closed"` and `"limit"`.

## Types

### `Options`

| Field | Meaning |
|---|---|
| `host as string` | router IP or DNS name |
| `port as int` | 8728 plain, 8729 api-ssl |
| `user as string` | API user |
| `password as string` | API password |
| `tls as bool` | api-ssl |
| `skipVerify as bool` | accept any certificate (`withSkipVerify`) |
| `caCert as bytes` | a PEM certificate to trust besides the system roots (`withCA`) |
| `allowInsecureAuth as bool` | log in over plain TCP anyway; default `false`, refused without `tls` |

### `Session`

| Field | Meaning |
|---|---|
| `socket as net.Conn` | the logged-in connection |

### `MikrotikError`

Every error of kind `"mikrotik"`.

| Field | Meaning |
|---|---|
| `kind as string` | always `"mikrotik"` |
| `message as string` | `mikrotik: !trap: <message>`, `mikrotik: !fatal: <message>`, or what went wrong |
| `reply as string` | `"trap"` or `"fatal"`; `""` for a local failure |
| `category as string` | a trap's category (`0` missing item or command, `1` bad argument, `2` interrupted, ...); `""` when none |
| `routerMessage as string` | the router's `message`; `""` when none |

## Connecting

| Function | Returns | Notes |
|---|---|---|
| `mikrotik.options(host, user, password)` | `Options` | plain TCP, port 8728, cleartext; `connect` needs `allowInsecureAuth` |
| `mikrotik.optionsTLS(host, user, password)` | `Options` | api-ssl, port 8729, certificate verified |
| `mikrotik.withPort(o, port)` | `Options` | another port |
| `mikrotik.withCA(o, pem)` | `Options` | trust a private CA or pinned certificate |
| `mikrotik.withSkipVerify(o)` | `Options` | accept any certificate |
| `mikrotik.insecure(o)` | `Options` | deprecated name of `withSkipVerify` |
| `mikrotik.connect(opts)` | `Session` | dial and log in (MD5 challenge for pre-6.43) |
| `mikrotik.close(session)` | | close the connection |

## Commands

| Function | Returns | Notes |
|---|---|---|
| `mikrotik.talk(session, command, attrs)` | `list of map of string to string` | one map per `!re` |
| `mikrotik.talkQuery(session, command, attrs, queries)` | `list of map of string to string` | plus `?` query words |
| `mikrotik.print(session, path)` | `list of map of string to string` | `path + "/print"` |
| `mikrotik.printWhere(session, path, queries)` | `list of map of string to string` | `path + "/print"` with query words |
| `mikrotik.run(session, command, attrs)` | `string` | the `!done`'s `=ret=`, `""` if none |

## Tags and streams

| Function | Returns | Notes |
|---|---|---|
| `mikrotik.talkTagged(session, command, attrs, tag)` | `list of map of string to string` | with a `.tag=` word; `""` generates one |
| `mikrotik.listen(session, command, params)` | `string` | start a streaming command, returns its tag |
| `mikrotik.receiveReply(session, tag)` | `map of string to string` | next pushed reply; `{}` once the stream ended |
| `mikrotik.cancel(session, tag)` | | `/cancel` the stream |
