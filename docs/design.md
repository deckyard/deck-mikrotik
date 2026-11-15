<!-- SPDX-License-Identifier: LGPL-3.0-only -->
<!-- SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev> -->

# Design

## Scope

The deck speaks the RouterOS binary API: login (plain, or the MD5 challenge of
routers before 6.43), commands with attribute and query words, tagged
commands, and streaming commands read reply by reply and stopped with
`/cancel`. It is the protocol layer; `@deckyard/routeros` builds typed
resources on top of it.

It leaves out:

- **The REST API** of RouterOS 7. It is HTTP and JSON, a different and
  stateless shape that `http` already reaches.
- **SSH.** The API needs no cryptography of its own (api-ssl is TLS), while an
  SSH client would bring key exchange and host-key handling.
- **Typed resources.** Rows are `map of string to string`, as the API sends
  them; parsing numbers and booleans is the caller's.

## Decisions

- **A deck, not a bundled module.** A client for one vendor's protocol belongs
  in the deck ecosystem. The deck is one of the bundled modules that
  `jennifer` moves out (M30.1 in its milestones) and keeps the module's
  surface, so migrating changes only the import.
- **One socket, read in order.** A synchronous call writes its sentence and
  reads to its `!done` before returning, so calls on one session must not
  overlap. A streaming command is read with `receiveReply`, which skips
  replies whose tag is not the one asked for.
- **A trap leaves the session usable.** The `!done` that follows a `!trap` is
  read before the error is thrown; a `!fatal` throws at once, since the router
  closes the connection.
- **A cancelled stream is not an error.** `receiveReply` takes the trap of
  category `2` (interrupted) that answers `/cancel` as the end of the stream
  and returns `{}`.
- **Strict words.** A query word must start with `?`, and an attribute name
  must be non-empty and hold no `=`, since RouterOS would read a different
  attribute. Values are sent as given.
- **Auto-generated tags** are UUIDs, so two streams on a session cannot
  collide.

## Errors

`MikrotikError` (kind `"mikrotik"`) is the one struct for every error of that
kind: a `!trap` (`reply` `"trap"`, the trap's `category`, the router's
`routerMessage`), a `!fatal` (`reply` `"fatal"`), and a refused query word or
attribute name (`reply` `""`).

The generic kinds go on unchanged: a socket failure (refused, reset,
unreachable, lookup, certificate) is `net`'s `net.NetError` (kind `"net"`), a
read past its deadline `"timeout"`, a router closing mid-sentence `"closed"`,
a word over the cap `"limit"`, and a cancelled task `"cancelled"`. The deck
catches nothing on its way, so none of them is rewrapped.

## Security and limits

- **Certificates are verified by default** on api-ssl. `withCA` pins a
  certificate and still authenticates the router; `insecure` turns
  authentication off.
- **Plain TCP is cleartext**, credentials included. `options` exists for a
  loopback or an otherwise secured link.
- **Deadlines.** Dialling and every read are bounded by 30 seconds, and each
  read clears its deadline on the way out, so it never carries over to the
  next read on the socket.
- **Word cap.** A word longer than 64 MiB is refused (kind `"limit"`) before
  anything is allocated for it.
- **A failed login closes the socket.**

## Testing and validation

`src/mikrotik_test.j` covers the word length codec, sentence parsing, command
building with its refusals, the MD5 challenge response and the error structs.
The exchanges run against a fake RouterOS API service on a loopback port that
answers with canned sentences: login (plain, the pre-6.43 challenge checked
against a response computed apart from the deck, and a refused one), print,
query and attribute words, `run`'s `=ret=`, a trap followed by a working call,
a `!fatal`, a word over the cap, tagged commands and a stream ended by
`/cancel`. A refused connection is shown to arrive as a `net.NetError`, a
close mid-sentence as `"closed"`. The api-ssl tests use an `httpd` TLS server
with a test CA: the default options refuse its certificate, `withCA` and
`insecure` get past the handshake.

The fake follows the RouterOS API documentation; the tests never reach a
router. The examples need one, so CI parses them only.

## Known limitations and open questions

- A reply's row count and a sentence's word count are not capped; only each
  word is. A hostile router can make a single reply large.
- No helper for typed values or for the `?#` query stack beyond passing the
  words through.

## Dependencies on the interpreter

- The floor is `>=0.26.0`, the release that deprecates the bundled module
  (M30.1).
- `net` with TLS, read deadlines and `net.NetError` (M28.65); thrown error
  structs (M28.50, M28.53). The `net` capability means the default `jennifer`
  binary only.
