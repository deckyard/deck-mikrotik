# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev>
# pragma-jennifer-version: >=0.28.0
# pragma-jennifer-capability: net

/**
 * A MikroTik RouterOS API client over `net` (not SSH). Connect to a router's
 * binary API (plain TCP 8728, or api-ssl 8729 over TLS), log in, and run
 * commands. The wire protocol is sentence-based: a sentence is a run of
 * length-prefixed words ending in a zero-length word; `talk` sends a command
 * sentence (`/interface/print`) with `=key=value` attribute words and folds
 * each `!re` reply sentence into a row map. `talkQuery` / `printWhere` add `?...`
 * query words to filter rows on the router. `print` is read sugar, `run` is for
 * mutating commands (returning the `!done`'s `=ret=`, e.g. a new item id).
 *
 * Login sends the name and password (`=name=` / `=password=`, RouterOS 6.43+ and
 * all v7), with an automatic MD5 challenge-response fallback for pre-6.43
 * routers. A `!trap`
 * or `!fatal` reply throws a `mikrotik.MikrotikError` (kind `"mikrotik"`) with
 * the reply, the trap's `category` and the router's message. The generic kinds
 * go on: a socket failure is `net`'s `net.NetError` (kind `"net"`), a deadline
 * `"timeout"`, a router closing mid-sentence `"closed"`, a reply over a cap
 * `"limit"`. Needs the default `jennifer` binary (`net`).
 *
 * SECURITY: `mikrotik.options` uses **cleartext** TCP (port 8728), so the
 * credentials and every command are readable on the wire. `connect` refuses to
 * log in over it unless `allowInsecureAuth` is set on the options; use
 * `mikrotik.optionsTLS` (api-ssl, port 8729) on any untrusted network. A
 * `CONNECT_TIMEOUT_MS` deadline bounds the dial and every read; a word is capped
 * at `MAX_WORD_BYTES` (64 MiB), a sentence at `MAX_SENTENCE_WORDS` words and one
 * reply at `MAX_REPLY_WORDS` words and `MAX_REPLY_BYTES` bytes, so a wedged or
 * hostile router cannot hang or OOM the program.
 * @module mikrotik
 * @example
 * import "@deckyard/mikrotik/" as mikrotik;
 * def o as mikrotik.Options init mikrotik.optionsTLS("192.168.88.1", "admin", "secret");
 * def s as mikrotik.Session init mikrotik.connect($o);
 * def ifaces as list of map of string to string init mikrotik.print($s, "/interface");
 * mikrotik.close($s);
 */
use net;
use binary;
use strings;
use maps;
use hash;
use encoding;
use uuid;
use channel;
use time;

/**
 * Connection options. `host` may be an IP or a DNS hostname (it is resolved when
 * the connection is dialled). For api-ssl (`tls`), the zero value **verifies**
 * the router's certificate against the system roots and the dialled host; a
 * self-signed or private-CA router needs `withCA` (trust a specific cert) or,
 * as a last resort, `withSkipVerify` (accept any cert).
 * @field host {string} the router host (IP or DNS name)
 * @field port {int} the API port (8728 plain, 8729 api-ssl)
 * @field user {string} the API username
 * @field password {string} the API password
 * @field tls {bool} whether to use api-ssl (TLS)
 * @field skipVerify {bool} accept *any* certificate (disables authentication; prefer `withCA`)
 * @field caCert {bytes} a PEM certificate to trust besides the system roots (a
 *   private CA or pinned cert)
 * @field allowInsecureAuth {bool} log in over plain TCP anyway (default false:
 *   refused without `tls`)
 */
export def struct Options {
    host as string,
    port as int,
    user as string,
    password as string,
    tls as bool,
    skipVerify as bool,
    caCert as bytes,
    allowInsecureAuth as bool
};

/**
 * An open, logged-in API session. Copies share the connection and the replies
 * held for later. One task at a time may call into a session: calls on it must
 * not overlap.
 * @field socket {net.Conn} the underlying (plain or TLS) connection
 * @field pending {channel of Sentence} internal: replies of other tags read
 *   while waiting for a reply, held for the call that reads their tag
 * @field pendingLeft {channel of Budget} internal: what `pending` may still hold
 */
export def struct Session {
    socket as net.Conn,
    pending as channel of Sentence,
    pendingLeft as channel of Budget
};

/**
 * A failed RouterOS API exchange. Every error of kind `"mikrotik"` is one, so
 * its fields are safe to read once the kind matches.
 * @field kind {string} always `"mikrotik"`
 * @field message {string} `mikrotik: !trap: <message>`, `mikrotik: !fatal:
 *   <message>`, or what went wrong
 * @field reply {string} `"trap"` (the command failed) or `"fatal"` (the router
 *   closed the connection); "" for another failure
 * @field category {string} a trap's `category` as the router sent it (`0`
 *   missing item or command, `1` argument value failure, `2` interrupted, `3`
 *   scripting failure, `4` general failure, `5` API failure, ...); "" when none
 * @field routerMessage {string} the router's `message`, "" when it sent none
 * @example
 * try {
 *     mikrotik.run($s, "/ip/address/add", {"address": "10.0.0.1/24", "interface": "ether9"});
 * } catch (e) {
 *     if ($e.kind == "mikrotik" and $e.reply == "trap") {
 *         io.printf("refused: %s\n", $e.routerMessage);
 *     } else {
 *         throw $e;
 *     }
 * }
 */
export def struct MikrotikError {
    kind as string,
    message as string,
    reply as string,
    category as string,
    routerMessage as string
};

func fail(msg as string) {
    throw MikrotikError{
        kind: "mikrotik",
        message: "mikrotik: " + $msg,
        reply: "",
        category: "",
        routerMessage: ""
    };
}

# fieldOr returns a reply field, or "" when the sentence did not carry it.
func fieldOr(fields as map of string to string, key as string) {
    if (maps.has($fields, $key)) {
        return $fields[$key];
    }
    return "";
}

# replyError throws the MikrotikError of a `!trap` or `!fatal` sentence's fields.
func replyError(reply as string, fields as map of string to string) {
    throw replyErrorOf($reply, $fields);
}

# replyErrorOf is the MikrotikError of a `!trap` or `!fatal` sentence's fields.
func replyErrorOf(reply as string, fields as map of string to string) {
    def text as string init "";
    if (maps.has($fields, "message")) {
        $text = $fields["message"];
    }
    def category as string init "";
    if (maps.has($fields, "category")) {
        $category = $fields["category"];
    }
    def shown as string init $text;
    if ($shown == "") {
        $shown = "command failed";
        if ($reply == "fatal") {
            $shown = "connection error";
        }
    }
    return MikrotikError{
        kind: "mikrotik",
        message: "mikrotik: !" + $reply + ": " + $shown,
        reply: $reply,
        category: $category,
        routerMessage: $text
    };
}

# Deadlines (ms). The dial is bounded by CONNECT_TIMEOUT_MS. Every read stalls
# for at most IDLE_TIMEOUT_MS, and a whole reply (every sentence up to `!done`,
# or one pushed sentence of a stream) must arrive within EXCHANGE_TIMEOUT_MS, so
# a router that trickles bytes cannot hold a call open. A sentence must be
# written within WRITE_TIMEOUT_MS.
def const CONNECT_TIMEOUT_MS as int init 30000;
def const IDLE_TIMEOUT_MS as int init 30000;
def const EXCHANGE_TIMEOUT_MS as int init 300000;
def const WRITE_TIMEOUT_MS as int init 30000;

# Cap on a server-declared word length (64 MiB, the tree-wide house rule). The
# API length prefix is up to a 32-bit value read straight off the wire; without
# this a hostile or MITM'd router (plaintext by default) declaring ~4 GiB would
# drive `readN` to OOM the recover-less interpreter.
def const MAX_WORD_BYTES as int init 67108864;

# Caps on what one reply may hold besides the word cap: words in one sentence
# (a row of a few dozen fields is normal, a few hundred rare), and the words and
# word bytes of every sentence up to `!done` together. Each word costs far more
# memory as a string in a row map than its bytes on the wire, so the word count
# is what bounds memory for a flood of short words.
def const MAX_SENTENCE_WORDS as int init 4096;
def const MAX_REPLY_WORDS as int init 262144;
def const MAX_REPLY_BYTES as int init 67108864;

# Caps on the sentences of other tags held for later (see `Session`): their
# number, and their words and bytes together (the reply caps again).
def const MAX_PENDING_SENTENCES as int init 4096;

# The tag prefix of `cancel`'s own `/cancel` sentence; replies carrying it are
# dropped wherever they are read.
def const CANCEL_TAG_PREFIX as string init "mikrotik-cancel-";

# Budget is what the rest of a reply may still hold (private).
def struct Budget {
    words as int,
    bytes as int
};

# Sentence is one sentence read off the wire (private): its words, their bytes,
# its `.tag` ("" for none), and `bad`, the first word that was not UTF-8 ("" when
# every word decoded; such a word is held as "").
def struct Sentence {
    words as list of string,
    bytes as int,
    tag as string,
    bad as string
};

func replyBudget() {
    return Budget{words: MAX_REPLY_WORDS, bytes: MAX_REPLY_BYTES};
}

func overCap(msg as string) {
    throw Error{kind: "limit", message: "mikrotik: " + $msg};
}

# malformed throws the MikrotikError of a reply that breaks the wire format.
func malformed(msg as string) {
    fail("malformed reply: " + $msg);
}

# checkWordLen rejects a server-declared word length outside [0, MAX_WORD_BYTES]
# before it is used to size a read. Over the cap is the generic kind "limit".
func checkWordLen(n as int) {
    if ($n < 0) {
        fail("word length out of range: {$n}");
    }
    if ($n > MAX_WORD_BYTES) {
        throw Error{
            kind: "limit",
            message: "mikrotik: word length {$n} exceeds the cap of {MAX_WORD_BYTES} bytes"
        };
    }
    return;
}

# --- options (exported) -----------------------------------------------------

/**
 * Plain-TCP options (port 8728). SECURITY: this transport is **cleartext** - the
 * login exchange and every command travel unencrypted, so an on-path attacker
 * reads the router's admin credentials. `connect` refuses these options until
 * the caller sets `allowInsecureAuth` to true. Prefer `optionsTLS` (api-ssl, port
 * 8729) on any network you do not fully trust; use `options` only on a loopback
 * or an otherwise-secured link.
 * @param host {string} the router host
 * @param user {string} the API username
 * @param password {string} the API password
 * @return {Options} the options
 */
export func options(host as string, user as string, password as string) {
    def o as Options;
    $o.host = $host;
    $o.port = 8728;
    $o.user = $user;
    $o.password = $password;
    $o.tls = false;
    return $o;
}

/**
 * api-ssl (TLS) options (port 8729). The router's certificate is **verified** by
 * default (against the system roots and the dialled host, IP or DNS name). For a
 * self-signed or private-CA router, add `withCA` (preferred) or `withSkipVerify`.
 * @param host {string} the router host (IP or DNS name)
 * @param user {string} the API username
 * @param password {string} the API password
 * @return {Options} the options
 */
export func optionsTLS(host as string, user as string, password as string) {
    def o as Options;
    $o.host = $host;
    $o.port = 8729;
    $o.user = $user;
    $o.password = $password;
    $o.tls = true;
    return $o;
}

/**
 * Copy options with a different port.
 * @param o {Options} the options
 * @param port {int} the port
 * @return {Options} a fresh options
 */
export func withPort(o as Options, port as int) {
    def out as Options init $o;
    $out.port = $port;
    return $out;
}

/**
 * Copy options that trust a specific PEM certificate (a private CA or a pinned
 * self-signed router cert) in addition to the system roots. The preferred way to
 * reach a self-signed api-ssl router: the peer is still authenticated, just
 * against this certificate.
 * @param o {Options} the options
 * @param pem {bytes} a PEM certificate to trust
 * @return {Options} a fresh options
 */
export func withCA(o as Options, pem as bytes) {
    def out as Options init $o;
    $out.caCert = $pem;
    return $out;
}

/**
 * Copy options that skip TLS certificate verification entirely. SECURITY: this
 * disables server authentication and exposes the session to a man-in-the-middle;
 * TLS still encrypts, but you no longer know who you are talking to. Prefer
 * `withCA`. Use only for a trusted-wire bootstrap of a self-signed router where
 * you cannot supply its certificate.
 * @param o {Options} the options
 * @return {Options} a fresh options
 */
export func withSkipVerify(o as Options) {
    def out as Options init $o;
    $out.skipVerify = true;
    return $out;
}

# --- byte + word codec (private) --------------------------------------------

# readN reads exactly `n` bytes. The deadlines are armed by the caller.
func readN(socket as net.Conn, n as int) {
    def parts as list of bytes init [];
    def got as int init 0;
    while ($got < $n) {
        def chunk as bytes init net.readBytes($socket, $n - $got);
        if (len($chunk) == 0) {
            throw Error{kind: "closed", message: "mikrotik: connection closed mid-sentence"};
        }
        # Collect the chunks and join once (binary.join, native Go copy) rather
        # than feeding every byte of the read through the interpreter.
        $parts[] = $chunk;
        $got = $got + len($chunk);
    }
    return binary.join($parts);
}

# encodeLen encodes a word length with RouterOS's variable-length scheme.
func encodeLen(n as int) {
    def b as bytes;
    if ($n < 0x80) {
        $b[] = $n;
    } elseif ($n < 0x4000) {
        $b[] = ($n >> 8) | 0x80;
        $b[] = $n & 0xff;
    } elseif ($n < 0x200000) {
        $b[] = ($n >> 16) | 0xc0;
        $b[] = ($n >> 8) & 0xff;
        $b[] = $n & 0xff;
    } elseif ($n < 0x10000000) {
        $b[] = ($n >> 24) | 0xe0;
        $b[] = ($n >> 16) & 0xff;
        $b[] = ($n >> 8) & 0xff;
        $b[] = $n & 0xff;
    } else {
        $b[] = 0xf0;
        $b[] = ($n >> 24) & 0xff;
        $b[] = ($n >> 16) & 0xff;
        $b[] = ($n >> 8) & 0xff;
        $b[] = $n & 0xff;
    }
    return $b;
}

# lenPrefixSize returns how many bytes a length prefix occupies, from its first
# byte.
func lenPrefixSize(head as int) {
    if (($head & 0x80) == 0) {
        return 1;
    }
    if (($head & 0xc0) == 0x80) {
        return 2;
    }
    if (($head & 0xe0) == 0xc0) {
        return 3;
    }
    if (($head & 0xf0) == 0xe0) {
        return 4;
    }
    return 5;
}

# minLenOfSize is the smallest length a prefix of `size` bytes may carry: a
# shorter one has a shorter (canonical) form.
func minLenOfSize(size as int) {
    if ($size == 2) {
        return 0x80;
    }
    if ($size == 3) {
        return 0x4000;
    }
    if ($size == 4) {
        return 0x200000;
    }
    if ($size == 5) {
        return 0x10000000;
    }
    return 0;
}

# decodeLen decodes the length prefix that starts at `off` in `buf`.
func decodeLen(buf as bytes, off as int) {
    def head as int init $buf[$off];
    def size as int init lenPrefixSize($head);
    if ($size == 1) {
        return $head;
    }
    if ($size == 2) {
        return (($head & 0x3f) << 8) | $buf[$off + 1];
    }
    if ($size == 3) {
        return (($head & 0x1f) << 16) | ($buf[$off + 1] << 8) | $buf[$off + 2];
    }
    if ($size == 4) {
        return (($head & 0x0f) << 24) |
            ($buf[$off + 1] << 16) | ($buf[$off + 2] << 8) | $buf[$off +
            3];
    }
    return ($buf[$off + 1] << 24) | ($buf[$off + 2] << 16) | ($buf[$off + 3] << 8) | $buf[$off + 4];
}

# readLenAfter reads the rest of a word length prefix whose first byte `head`
# was already read, and decodes it. The API reserves first bytes 0xF8 and up
# (control bytes), and a length is always sent in its shortest form; anything
# else is malformed.
func readLenAfter(socket as net.Conn, head as int) {
    if ($head >= 0xf8) {
        def hb as bytes;
        $hb[] = $head;
        malformed("reserved length byte 0x" + encoding.toText("hex", $hb));
    }
    def size as int init lenPrefixSize($head);
    if ($size == 1) {
        return $head;
    }
    def buf as bytes;
    $buf[] = $head;
    $buf = binary.concat($buf, readN($socket, $size - 1));
    def n as int init decodeLen($buf, 0);
    if ($n < minLenOfSize($size)) {
        malformed("length {$n} not in its shortest form");
    }
    return $n;
}

# readLen reads and decodes a word length prefix off the socket.
func readLen(socket as net.Conn) {
    return readLenAfter($socket, readN($socket, 1)[0]);
}

# encodeSentence encodes a run of words plus the zero-length terminator.
func encodeSentence(words as list of string) {
    def parts as list of bytes init [];
    for (def w in $words) {
        def raw as bytes init encoding.encode("utf-8", $w);
        $parts[] = encodeLen(len($raw));
        $parts[] = $raw;
    }
    $parts[] = encodeLen(0);
    return binary.join($parts);
}

# writeSentence writes a sentence in one write, within WRITE_TIMEOUT_MS.
func writeSentence(socket as net.Conn, words as list of string) {
    net.setWriteDeadline($socket, WRITE_TIMEOUT_MS);
    net.writeBytes($socket, encodeSentence($words));
    net.setWriteDeadline($socket, 0);
}

# wordName names a word that is not UTF-8 for an error: the field of an
# `=key=value` word when its key decodes, else its position.
func wordName(raw as bytes, index as int) {
    def eq as bytes init encoding.encode("utf-8", "=");
    if (not binary.startsWith($raw, $eq)) {
        return "word {$index}";
    }
    def end as int init binary.indexOf($raw, $eq, 1, 256);
    if ($end <= 1) {
        return "word {$index}";
    }
    try {
        return "field \"" + encoding.decode("utf-8", $raw[1..$end]) + "\"";
    } catch (e) {
        if ($e.kind != "encoding") {
            throw $e;
        }
    }
    return "word {$index}";
}

# readSentenceAfter reads words until the zero-length terminator; `head` is
# the first byte of the first length prefix when the caller already read it,
# else -1. Each length is checked before its word is read: past
# MAX_SENTENCE_WORDS words, or past what is `left` of the reply's budget, it
# throws kind "limit". A word that is not UTF-8 is held as "" and named in
# `bad`, so the caller can finish the reply before it throws.
func readSentenceAfter(socket as net.Conn, left as Budget, head as int) {
    def words as list of string init [];
    def size as int init 0;
    def tag as string init "";
    def bad as string init "";
    def first as int init $head;
    while (true) {
        def n as int init 0;
        if ($first >= 0) {
            $n = readLenAfter($socket, $first);
            $first = -1;
        } else {
            $n = readLen($socket);
        }
        if ($n == 0) {
            if (len($words) == 0) {
                malformed("empty sentence");
            }
            return Sentence{words: $words, bytes: $size, tag: $tag, bad: $bad};
        }
        checkWordLen($n);
        def count as int init len($words);
        if ($count >= MAX_SENTENCE_WORDS) {
            overCap("a sentence holds more than {MAX_SENTENCE_WORDS} words");
        }
        if ($count >= $left.words) {
            overCap("a reply holds more than {MAX_REPLY_WORDS} words");
        }
        if ($size + $n > $left.bytes) {
            overCap("a reply exceeds the cap of {MAX_REPLY_BYTES} bytes");
        }
        def raw as bytes init readN($socket, $n);
        def word as string init "";
        try {
            $word = encoding.decode("utf-8", $raw);
        } catch (e) {
            if ($e.kind != "encoding") {
                throw $e;
            }
            if ($bad == "") {
                $bad = wordName($raw, $count);
            }
        }
        if (strings.startsWith($word, ".tag=")) {
            $tag = $word[5..];
        }
        $words[] = $word;
        $size = $size + $n;
    }
}

# readSentenceWithin reads one sentence within `left`.
func readSentenceWithin(socket as net.Conn, left as Budget) {
    return readSentenceAfter($socket, $left, -1);
}

# readSentence reads one sentence on its own, within a whole reply's budget.
func readSentence(socket as net.Conn) {
    return readSentenceWithin($socket, replyBudget()).words;
}

# --- sentence <-> row mapping (private) -------------------------------------

# parseFields folds a sentence's `=key=value` words (after the reply word) into
# a map.
func parseFields(sentence as list of string) {
    def fields as map of string to string init {};
    def i as int init 1;
    while ($i < len($sentence)) {
        def w as string init $sentence[$i];
        if (strings.startsWith($w, "=")) {
            def rest as string init $w[1..];
            def eq as int init strings.indexOf($rest, "=");
            if ($eq >= 0) {
                $fields[$rest[..$eq]] = $rest[$eq + 1..];
            }
        }
        $i = $i + 1;
    }
    return $fields;
}

# parseTag returns the value of a reply sentence's `.tag=<id>` word (the API tag
# word, distinct from the `=key=value` attribute words `parseFields` folds), or
# "" when the sentence carries no tag. Used to correlate a pushed reply back to
# the command that started it.
func parseTag(sentence as list of string) {
    for (def w in $sentence) {
        if (strings.startsWith($w, ".tag=")) {
            return $w[5..];
        }
    }
    return "";
}

# buildWords turns a command plus attribute and query words into a word list.
# Attribute words are `=key=value`; query words are raw RouterOS query words -
# each starts with `?` (e.g. `?type=ether`, `?>mtu=1000`, or a `?#&` / `?#|` /
# `?#!` stack operator) - and are appended verbatim, so the full query grammar
# stays reachable. A query word missing its leading `?` is a caller error.
func buildWords(command as string, attrs as map of string to string, queries as list of string) {
    def words as list of string init [$command];
    for (def key in $attrs) {
        # RouterOS reads `=key=value` up to the second `=`: a key holding `=`
        # would set a different attribute than the one named.
        if ($key == "" or strings.contains($key, "=")) {
            fail("attribute name must be non-empty and hold no '=': " + $key);
        }
        $words[] = "=" + $key + "=" + $attrs[$key];
    }
    for (def q in $queries) {
        if (not strings.startsWith($q, "?")) {
            fail("query word must start with '?': " + $q);
        }
        $words[] = $q;
    }
    return $words;
}

# buildTaggedWords is buildWords plus a trailing `.tag=<tag>` API word, so the
# router echoes the tag on every reply to this command and a later `/cancel` can
# name it. The command word stays first; the tag word (like every API word) may
# follow in any order.
func buildTaggedWords(
    command as string,
    attrs as map of string to string,
    queries as list of string,
    tag as string) {
    def words as list of string init buildWords($command, $attrs, $queries);
    $words[] = ".tag=" + $tag;
    return $words;
}

# buildCancelWords builds a `/cancel` sentence naming the tag to stop:
# ["/cancel", "=tag=<tag>"]. Sent to interrupt a streaming command started with
# that tag; the router answers the streaming command with `!trap` (category `2`,
# interrupted) then `!done`.
func buildCancelWords(tag as string) {
    return ["/cancel", "=tag=" + $tag];
}

# resolveTag returns the caller's tag when non-empty, else an auto-generated,
# collision-free one (a UUID, drawn from crypto-grade randomness).
func resolveTag(tag as string) {
    if (len($tag) == 0) {
        return uuid.v4();
    }
    return $tag;
}

# --- session state (private) ------------------------------------------------

# newSession wraps a connected socket: no held sentences, the full pending
# budget.
func newSession(socket as net.Conn) {
    def s as Session init Session{
        socket: $socket,
        pending: channel.make(MAX_PENDING_SENTENCES),
        pendingLeft: channel.make(1)
    };
    channel.send($s.pendingLeft, replyBudget());
    return $s;
}

# abandon closes a session whose connection is out of step with the protocol
# (a reply only partly read, a sentence only partly written): every later call
# on it throws kind "closed".
func abandon(session as Session) {
    try {
        net.close($session.socket);
    } catch (e) {
        if ($e.kind != "closed") {
            throw $e;
        }
    }
}

# hold keeps a sentence of another tag for the call that reads that tag. Past
# MAX_PENDING_SENTENCES sentences, or the reply caps for all of them, it throws
# kind "limit".
func hold(session as Session, s as Sentence) {
    if (channel.len($session.pending) >= MAX_PENDING_SENTENCES) {
        overCap("more than {MAX_PENDING_SENTENCES} sentences of other tags are waiting");
    }
    def left as Budget init channel.recv($session.pendingLeft);
    def fits as bool init len($s.words) <= $left.words and $s.bytes <= $left.bytes;
    if ($fits) {
        $left.words = $left.words - len($s.words);
        $left.bytes = $left.bytes -$s.bytes;
    }
    channel.send($session.pendingLeft, $left);
    if (not $fits) {
        overCap("the sentences of other tags waiting exceed the reply caps");
    }
    channel.send($session.pending, $s);
}

# taken is a held sentence looked up by tag (private).
def struct Taken {
    found as bool,
    sentence as Sentence
};

# takeHeld removes and returns the oldest held sentence for `tag` (any tag when
# `all`), keeping the others in order.
func takeHeld(session as Session, tag as string, all as bool) {
    def out as Taken;
    def n as int init channel.len($session.pending);
    if ($n == 0) {
        return $out;
    }
    for (def i in 0..$n) {
        def s as Sentence init channel.recv($session.pending);
        if (not $out.found and ($all or $s.tag == $tag)) {
            $out.found = true;
            $out.sentence = $s;
        } else {
            channel.send($session.pending, $s);
        }
    }
    if ($out.found) {
        def left as Budget init channel.recv($session.pendingLeft);
        $left.words = $left.words + len($out.sentence.words);
        $left.bytes = $left.bytes + $out.sentence.bytes;
        channel.send($session.pendingLeft, $left);
    }
    return $out;
}

# nextFor returns the next sentence for `tag` (any when `all`): a held one, else
# read off the wire, holding the sentences of other tags met on the way. The
# replies to `cancel`'s own `/cancel` are dropped.
func nextFor(session as Session, tag as string, all as bool, left as Budget) {
    def held as Taken init takeHeld($session, $tag, $all);
    if ($held.found) {
        return $held.sentence;
    }
    while (true) {
        def s as Sentence init readSentenceWithin($session.socket, $left);
        # A !fatal ends every command on the session, whatever its tag.
        if ($all or $s.tag == $tag or $s.words[0] == "!fatal") {
            return $s;
        }
        if (not strings.startsWith($s.tag, CANCEL_TAG_PREFIX)) {
            hold($session, $s);
        }
    }
}

# --- replies (private) ------------------------------------------------------

# One command's collected reply (private): the `!re` rows, the `!done` ret, and
# the error to throw once the reply was read to its `!done` (a `!trap`, or a
# word that is not UTF-8).
def struct Reply {
    rows as list of map of string to string,
    ret as string,
    failed as bool,
    failure as MikrotikError
};

# collectReplyWithin reads the sentences tagged `tag` ("" for an untagged
# command) to `!done`, held to `budget`, charged sentence by sentence (the tests
# pass a small one). Sentences of other tags are held for their readers. A
# `!trap`, or a word that is not UTF-8, is returned as the reply's failure once
# its `!done` is read; a `!fatal` throws at once.
func collectReplyWithin(session as Session, tag as string, budget as Budget) {
    def left as Budget init $budget;
    def out as Reply;
    def rows as list of map of string to string init [];
    def bad as string init "";
    def trapFields as map of string to string init {};
    def trapped as bool init false;
    def done as bool init false;
    repeat {
        def got as Sentence init nextFor($session, $tag, false, $left);
        def sentence as list of string init $got.words;
        $left.words = $left.words - len($sentence);
        $left.bytes = $left.bytes -$got.bytes;
        if ($bad == "") {
            $bad = $got.bad;
        }
        def reply as string init $sentence[0];
        def fields as map of string to string init parseFields($sentence);
        if ($reply == "!re") {
            $rows[] = $fields;
        } elseif ($reply == "!done") {
            $out.ret = fieldOr($fields, "ret");
            $done = true;
        } elseif ($reply == "!trap") {
            # A trap is followed by a !done; record it and keep reading so
            # the trailing !done is consumed before we raise.
            $trapped = true;
            $trapFields = $fields;
        } elseif ($reply == "!fatal") {
            # A fatal closes the connection - no !done follows, so raise now.
            replyError("fatal", $fields);
        }
    } until ($done);
    $out.rows = $rows;
    if ($trapped) {
        $out.failed = true;
        $out.failure = replyErrorOf("trap", $trapFields);
    } elseif ($bad != "") {
        $out.failed = true;
        $out.failure = notUtf8($bad);
    }
    return $out;
}

# notUtf8 is the MikrotikError of a reply word that is not UTF-8.
func notUtf8(what as string) {
    return MikrotikError{
        kind: "mikrotik",
        message: "mikrotik: reply " + $what + " is not UTF-8",
        reply: "",
        category: "",
        routerMessage: ""
    };
}

# exchangeWithin sends `words` and collects the reply tagged `tag` within
# `budget` and `deadlineMs` (the whole reply). A failure on the way abandons
# the session, whose socket is then out of step; a `!trap` or a word that is
# not UTF-8 throws after the `!done`, with the session still usable.
func exchangeWithin(
    session as Session,
    words as list of string,
    tag as string,
    budget as Budget,
    deadlineMs as int) {
    def r as Reply;
    try {
        writeSentence($session.socket, $words);
        net.setReadDeadline($session.socket, $deadlineMs);
        $r = collectReplyWithin($session, $tag, $budget);
        net.setReadDeadline($session.socket, 0);
    } catch (e) {
        abandon($session);
        throw $e;
    }
    if ($r.failed) {
        def failure as MikrotikError init $r.failure;
        throw $failure;
    }
    return $r;
}

# exchange sends a command and collects its reply to `!done`.
func exchange(
    session as Session,
    command as string,
    attrs as map of string to string,
    queries as list of string) {
    def words as list of string init buildWords($command, $attrs, $queries);
    return exchangeWithin($session, $words, "", replyBudget(), EXCHANGE_TIMEOUT_MS);
}

# send writes a sentence that is not answered here; a failed write abandons the
# session.
func send(session as Session, words as list of string) {
    try {
        writeSentence($session.socket, $words);
    } catch (e) {
        abandon($session);
        throw $e;
    }
}

# --- login (private) --------------------------------------------------------

# challengeResponse builds the pre-6.43 challenge response: "00" + hex(MD5(0x00 +
# password + challengeBytes)). The challenge is 16 bytes as 32 hex digits.
func challengeResponse(password as string, challengeHex as string) {
    def challenge as bytes;
    try {
        $challenge = encoding.fromText("hex", $challengeHex);
    } catch (e) {
        if ($e.kind != "encoding") {
            throw $e;
        }
    }
    if (len($challenge) != 16) {
        fail("login challenge is not 32 hex digits");
    }
    def input as bytes;
    $input[] = 0;
    $input = binary.concat($input, encoding.encode("utf-8", $password));
    $input = binary.concat($input, $challenge);
    return "00" + encoding.toText("hex", hash.compute("md5", $input));
}

func login(session as Session, user as string, password as string) {
    def attrs as map of string to string init {};
    $attrs["name"] = $user;
    $attrs["password"] = $password;
    def r as Reply init exchange($session, "/login", $attrs, []);
    # An old (pre-6.43) router answers with a challenge in =ret= instead of
    # logging in; complete the MD5 challenge-response.
    if (len($r.ret) > 0) {
        def resp as map of string to string init {};
        $resp["name"] = $user;
        $resp["response"] = challengeResponse($password, $r.ret);
        exchange($session, "/login", $resp, []);
    }
}

# --- API (exported) ---------------------------------------------------------

/**
 * Connect to a router and log in. Over plain TCP (`options`, no `tls`) the login
 * is refused before anything is dialled unless `allowInsecureAuth` is set, since
 * the password would cross the network in the clear.
 * @param opts {Options} the connection options
 * @return {Session} the logged-in session
 * @throws {MikrotikError} kind "mikrotik" on a login failure, or plain TCP
 *   without allowInsecureAuth
 */
export func connect(opts as Options) {
    if (not $opts.tls and not $opts.allowInsecureAuth) {
        fail("refusing to log in over the plaintext API (no TLS); use optionsTLS (api-ssl), " +
            "or set allowInsecureAuth to force");
    }
    def addr as string init "{$opts.host}:{$opts.port}";
    def socket as net.Conn;
    if ($opts.tls) {
        # api-ssl verifies the router's certificate by default (against the
        # system roots and the dialled host, IP or DNS name). A self-signed or
        # private-CA router opts out per-connection: `withCA` pins its cert
        # (still authenticated) or `withSkipVerify` accepts any cert. The zero Options
        # maps to a zero net.TLSOptions - full verification.
        def tlsOpts as net.TLSOptions;
        $tlsOpts.skipVerify = $opts.skipVerify;
        $tlsOpts.caCert = $opts.caCert;
        $socket = net.connectWith(
            $addr,
            net.ConnectOptions{timeoutMs: CONNECT_TIMEOUT_MS, tls: true, tlsOptions: $tlsOpts});
    } else {
        $socket = net.connectWith($addr, net.ConnectOptions{timeoutMs: CONNECT_TIMEOUT_MS});
    }
    # A refused login must not leak the socket; on success the caller owns the
    # open session.
    errdefer net.close($socket);
    net.setIdleTimeout($socket, IDLE_TIMEOUT_MS);
    def session as Session init newSession($socket);
    login($session, $opts.user, $opts.password);
    return $session;
}

/**
 * Run a command with attribute words and return the `!re` reply rows (each a
 * `=key=value` map). The general call - reads, adds, sets, and removes all go
 * through it.
 * @param session {Session} the session
 * @param command {string} the API command (e.g. "/interface/print")
 * @param attrs {map of string to string} attribute words ({} for none)
 * @return {list of map of string to string} the reply rows
 * @throws {MikrotikError} kind "mikrotik" on a !trap / !fatal reply
 */
export func talk(session as Session, command as string, attrs as map of string to string) {
    return exchange($session, $command, $attrs, []).rows;
}

/**
 * Like `talk`, but also sends RouterOS **query words** to filter the reply on the
 * router. Each query word is raw and starts with `?`: `?type=ether` (property
 * equals), `?disabled` (property present), `?>mtu=1000` (greater), plus the stack
 * operators `?#!` / `?#&` / `?#|` for compound queries. Attribute words still
 * apply (e.g. `=.proplist=name,type` to trim the columns). The general filtered
 * read the higher-level helpers build on.
 * @param session {Session} the session
 * @param command {string} the API command (e.g. "/interface/print")
 * @param attrs {map of string to string} attribute words ({} for none)
 * @param queries {list of string} raw query words, each starting with "?"
 * @return {list of map of string to string} the matching reply rows
 * @throws {MikrotikError} kind "mikrotik" on a bad query word or a !trap / !fatal reply
 */
export func talkQuery(
    session as Session,
    command as string,
    attrs as map of string to string,
    queries as list of string) {
    return exchange($session, $command, $attrs, $queries).rows;
}

/**
 * Read sugar: run `path + "/print"` with no attributes.
 * @param session {Session} the session
 * @param path {string} the menu path (e.g. "/interface")
 * @return {list of map of string to string} the reply rows
 * @throws {MikrotikError} kind "mikrotik" on a !trap / !fatal reply
 */
export func print(session as Session, path as string) {
    def none as map of string to string init {};
    return exchange($session, $path + "/print", $none, []).rows;
}

/**
 * Read sugar: run `path + "/print"` filtered by query words (no attributes) -
 * `printWhere($s, "/interface", ["?type=ether"])` returns only the ether ports.
 * @param session {Session} the session
 * @param path {string} the menu path (e.g. "/interface")
 * @param queries {list of string} raw query words, each starting with "?"
 * @return {list of map of string to string} the matching reply rows
 * @throws {MikrotikError} kind "mikrotik" on a bad query word or a !trap / !fatal reply
 */
export func printWhere(session as Session, path as string, queries as list of string) {
    def none as map of string to string init {};
    return exchange($session, $path + "/print", $none, $queries).rows;
}

/**
 * Run a mutating command (add / set / remove) and return the `!done` `=ret=`
 * value (e.g. the new item's id for `add`; "" when there is none).
 * @param session {Session} the session
 * @param command {string} the API command (e.g. "/ip/address/add")
 * @param attrs {map of string to string} attribute words
 * @return {string} the `=ret=` value, or ""
 * @throws {MikrotikError} kind "mikrotik" on a !trap / !fatal reply
 */
export func run(session as Session, command as string, attrs as map of string to string) {
    return exchange($session, $command, $attrs, []).ret;
}

# --- tagging + streaming (exported) -----------------------------------------

/**
 * Like `talk`, but attaches a `.tag=<id>` word so the router echoes the tag on
 * every reply. Only the replies carrying the tag are collected; replies of other
 * tags (a running `listen` stream) read on the way are held for their reader.
 * Pass `tag: ""` to auto-generate a unique tag. The reply is still collected to
 * `!done` (a one-shot command); for a command that pushes replies over time use
 * `listen` + `receiveReply`.
 * @param session {Session} the session
 * @param command {string} the API command (e.g. "/interface/print")
 * @param attrs {map of string to string} attribute words ({} for none)
 * @param tag {string} the correlation tag, or "" to auto-generate one
 * @return {list of map of string to string} the reply rows
 * @throws {MikrotikError} kind "mikrotik" on a !trap / !fatal reply
 */
export func talkTagged(
    session as Session,
    command as string,
    attrs as map of string to string,
    tag as string) {
    def t as string init resolveTag($tag);
    def noq as list of string init [];
    def words as list of string init buildTaggedWords($command, $attrs, $noq, $t);
    return exchangeWithin($session, $words, $t, replyBudget(), EXCHANGE_TIMEOUT_MS).rows;
}

/**
 * Start a **streaming** command (one that pushes `!re` sentences over time, e.g.
 * "/interface/monitor" or "/ping") and return its auto-generated tag. Does NOT
 * read a reply - the stream has no `!done` until it is stopped. Pull each pushed
 * reply with `receiveReply($s, tag)` (typically from a `spawn`ed loop), and stop
 * it with `cancel($s, tag)`.
 * @param session {Session} the session
 * @param command {string} the streaming API command
 * @param params {map of string to string} attribute words for the command ({} for none)
 * @return {string} the tag naming this stream (feed it to receiveReply / cancel)
 */
export func listen(session as Session, command as string, params as map of string to string) {
    def tag as string init uuid.v4();
    def noq as list of string init [];
    send($session, buildTaggedWords($command, $params, $noq, $tag));
    return $tag;
}

/**
 * Block until the next pushed reply for `tag` arrives and return it as a
 * `=key=value` field map; `receiveReplyWithin` with a 30-second wait.
 * @param session {Session} the session
 * @param tag {string} the stream tag returned by `listen`
 * @return {map of string to string} the next reply's fields, or {} at stream end
 * @throws {MikrotikError} kind "mikrotik" on a genuine !trap / !fatal reply
 */
export func receiveReply(session as Session, tag as string) {
    return receiveReplyWithin($session, $tag, CONNECT_TIMEOUT_MS);
}

/**
 * Wait up to `timeoutMs` for the next pushed reply for `tag` and return it as a
 * `=key=value` field map. Returns an **empty map** when the stream has ended (a
 * `!done` for the tag - e.g. after `cancel`), which is the loop's stop signal.
 * Replies of other tags read on the way are held for their reader. A
 * `cancel`-induced `!trap` (category `2`, interrupted) is absorbed; any other
 * `!trap` of the tag, or a `!fatal`, throws. When nothing arrives in time it
 * throws kind `"timeout"` and the session stays usable (call again, or
 * `cancel`); once a reply has begun it must arrive within the exchange deadline.
 * @param session {Session} the session
 * @param tag {string} the stream tag returned by `listen`
 * @param timeoutMs {int} how long to wait in ms; 0 waits without a limit
 * @return {map of string to string} the next reply's fields, or {} at stream end
 * @throws {MikrotikError} kind "mikrotik" on a genuine !trap / !fatal reply or a
 *   negative timeout
 */
export func receiveReplyWithin(session as Session, tag as string, timeoutMs as int) {
    if ($timeoutMs < 0) {
        fail("timeoutMs must be >= 0, got {$timeoutMs}");
    }
    def all as bool init len($tag) == 0;
    def endAt as int init time.unixMilliseconds(time.now()) + $timeoutMs;
    while (true) {
        def held as Taken init takeHeld($session, $tag, $all);
        def s as Sentence;
        if ($held.found) {
            $s = $held.sentence;
        } else {
            $s = waitSentence($session, $timeoutMs, $endAt);
        }
        if ($all or $s.tag == $tag) {
            def reply as string init $s.words[0];
            def fields as map of string to string init parseFields($s.words);
            if ($reply == "!fatal") {
                abandon($session);
                replyError("fatal", $fields);
            }
            if ($s.bad != "") {
                throw notUtf8($s.bad);
            }
            if ($reply == "!re") {
                return $fields;
            }
            if ($reply == "!done") {
                return {};
            }
            # A cancel interrupts the streaming command with a trap of category
            # 2 (interrupted); it is normal end-of-stream, not an error, so keep
            # reading for the trailing !done.
            if ($reply == "!trap" and fieldOr($fields, "category") != "2") {
                replyError("trap", $fields);
            }
        } elseif ($s.words[0] == "!fatal") {
            abandon($session);
            replyError("fatal", parseFields($s.words));
        } elseif (not strings.startsWith($s.tag, CANCEL_TAG_PREFIX)) {
            hold($session, $s);
        }
    }
}

# waitSentence reads the next sentence off the wire: it waits for its first
# byte until `until` (ms since the epoch; none when `timeoutMs` is 0), then
# reads the rest within the exchange deadline. Nothing is consumed by a timeout
# while waiting, so the session stays usable; a failure after the first byte
# abandons it.
func waitSentence(session as Session, timeoutMs as int, endAt as int) {
    def socket as net.Conn init $session.socket;
    def wait as int init 0;
    if ($timeoutMs > 0) {
        $wait = $endAt - time.unixMilliseconds(time.now());
        if ($wait <= 0) {
            throw Error{kind: "timeout", message: "mikrotik: no reply within {$timeoutMs} ms"};
        }
    }
    def head as int init -1;
    try {
        net.setIdleTimeout($socket, 0);
        net.setReadDeadline($socket, $wait);
        $head = readN($socket, 1)[0];
    } catch (e) {
        if ($e.kind != "timeout" and $e.kind != "cancelled") {
            abandon($session);
        }
        throw $e;
    }
    try {
        net.setIdleTimeout($socket, IDLE_TIMEOUT_MS);
        net.setReadDeadline($socket, EXCHANGE_TIMEOUT_MS);
        def s as Sentence init readSentenceAfter($socket, replyBudget(), $head);
        net.setReadDeadline($socket, 0);
        return $s;
    } catch (e) {
        abandon($session);
        throw $e;
    }
}

/**
 * Stop a streaming command started with `listen` by issuing `/cancel` naming its
 * tag. Fire-and-forget: the resulting `!trap` (interrupted) and `!done` for the
 * stream are read by the `receiveReply` loop (which then returns {} and lets the
 * loop exit); the `/cancel`'s own reply is dropped.
 * @param session {Session} the session
 * @param tag {string} the stream tag returned by `listen`
 */
export func cancel(session as Session, tag as string) {
    def words as list of string init buildCancelWords($tag);
    $words[] = ".tag=" + CANCEL_TAG_PREFIX + uuid.v4();
    send($session, $words);
}

/**
 * Close the session's connection. Closing a session that a failure already
 * closed does nothing.
 * @param session {Session} the session
 */
export func close(session as Session) {
    abandon($session);
}

/**
 * The old name of `withSkipVerify` (stance 8: one name per builder across
 * modules and decks).
 * @param o {Options} the options
 * @return {Options} a fresh options
 * @deprecated use `withSkipVerify`; removed in the next minor release
 */
export func insecure(o as Options) {
    return withSkipVerify($o);
}
