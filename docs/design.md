<!-- SPDX-License-Identifier: LGPL-3.0-only -->
<!-- SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev> -->

# Design

## Scope

The deck speaks the RouterOS™ binary API: login (plain, or the MD5 challenge of
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
- **One socket, one reader, replies routed by tag.** A synchronous call
  writes its sentence (in one write) and reads to its `!done` before
  returning, so calls on one session must not overlap. Every read takes only
  the sentences of its own tag (`""` for an untagged command); sentences of
  other tags met on the way are held in the session's `pending` channel (a
  shared handle, so copies of the `Session` see one queue) for the call that
  reads their tag. A `talk` while a stream runs, and two streams on one
  session, lose nothing. The queue is capped like a reply (4096 sentences,
  262144 words, 64 MiB). `cancel` tags its own `/cancel`, and replies to it
  are dropped wherever they are read; a `!fatal` of any tag ends the call.
- **A trap leaves the session usable; a half-read reply closes it.** The
  `!done` that follows a `!trap` is read before the error is thrown. Any
  other failure while a sentence is written or a reply read (a cap, a
  deadline, a malformed reply, a `!fatal`) leaves the connection out of step
  with the protocol, so the session's socket is closed and every later call
  is kind `"closed"` (`close` on it does nothing). Reading on would take the
  rest of the failed reply as the next one.
- **Strict replies.** Every word must be UTF-8: RouterOS stores the bytes a
  client sent, so a comment typed in a legacy code page is possible, and it is
  reported (a `MikrotikError` naming the field, after the reply's `!done`)
  rather than decoded into something else. A length prefix must use its
  shortest form and not a reserved first byte (`0xF8` and up); an empty
  sentence and a login challenge that is not 32 hex digits are malformed.
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
`routerMessage`), a `!fatal` (`reply` `"fatal"`), and a refused query word,
attribute name or plain-TCP login, a reply word that is not UTF-8, and a
malformed reply (`reply` `""`).

The generic kinds go on unchanged: a socket failure (refused, reset,
unreachable, lookup, certificate) is `net`'s `net.NetError` (kind `"net"`), a
read past its deadline `"timeout"`, a router closing mid-sentence `"closed"`,
a reply over a cap `"limit"`, and a cancelled task `"cancelled"`. The deck
catches nothing on its way, so none of them is rewrapped.

## Security and limits

- **Certificates are verified by default** on api-ssl. `withCA` pins a
  certificate and still authenticates the router; `withSkipVerify` turns
  authentication off.
- **Plain TCP is cleartext**, credentials included, so `connect` refuses a
  login over it before dialling unless `allowInsecureAuth` is set (the field
  `smtp` uses for the same choice). `options` exists for a loopback or an
  otherwise secured link, where the caller says so.
- **Deadlines.** Dialling is bounded by 30 seconds, and every read by an idle
  timeout of 30 seconds (a stall). A whole reply must arrive within 5 minutes
  (`EXCHANGE_TIMEOUT_MS`), so a router trickling bytes inside the idle
  timeout cannot hold a call open; the deadline is armed once per exchange,
  not per read. A sentence must be written within 30 seconds, so a router that
  stops reading cannot block a write. `receiveReply` waits 30 seconds for the
  next pushed reply; `receiveReplyWithin` takes the wait (0 for none), lifts
  the idle timeout until the first byte, and leaves the session usable when
  the wait runs out with nothing read. Once a sentence has begun, it is held
  to the idle timeout and the exchange deadline.
- **Reply caps.** A word longer than 64 MiB, a sentence of more than 4096
  words, and a reply (every sentence to `!done`) of more than 262144 words or
  64 MiB of word text are refused (kind `"limit"`) before the excess is read.
  The word count is what bounds memory: each word becomes a string in a row
  map, at over a kilobyte apiece: a reply at the word cap peaked at 320 MB
  (wide rows) to 370 MB (two-word rows), where a million short words in one
  sentence took 1.2 GB before the caps.
  `receiveReply` holds each pushed sentence to the same caps.
- **The session is closed** after a reply over a cap, so its rest is never
  read.
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
close mid-sentence as `"closed"`. A scripted router sends raw replies: a reply
failing half read closes the session; tagged replies interleaved with another
tag's, a `talk` while a stream runs, and two streams with a trap in one reach
the right reader; a reply trickled inside the idle timeout hits a short
exchange deadline; a quiet stream waits past the idle timeout and a short wait
leaves the session usable; a non-UTF-8 field, an empty sentence, reserved and
overlong length prefixes and a bad login challenge are `MikrotikError`s. A
write to a peer that does not read times out. A plain-TCP login is refused before
dialling without `allowInsecureAuth` and dials with it; a sentence one word
over the cap, and replies over a small word or byte budget, are `"limit"`. The api-ssl tests use an `httpd` TLS server
with a test CA: the default options refuse its certificate, `withCA` and
`withSkipVerify` get past the handshake.

The fake follows the RouterOS API documentation; the tests never reach a
router. The examples need one, so CI parses them only.

## Known limitations and open questions

- No helper for typed values or for the `?#` query stack beyond passing the
  words through.

## Dependencies on the interpreter

- The floor is `>=0.28.0` (the calls 0.29.0 removes are replaced by their 0.28.0 forms), for the UTF-8 codecs of `encoding.encode` /
  `decode`; the bundled module is deprecated from 0.26.0 (M30.1).
- `net` with TLS, read deadlines and `net.NetError` (M28.65); thrown error
  structs (M28.50, M28.53). The `net` capability means the default `jennifer`
  binary only.
