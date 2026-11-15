# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev>
# pragma-jennifer-version: >=0.26.0

/**
 * White-box tests for the entry module: jennifer test src/mikrotik_test.j
 *
 * The word length codec, sentence parsing and command building are tested
 * directly. The exchanges (login, talk, query words, run, traps, tagged
 * commands, /listen streams) run against `fakeRouter`, a RouterOS API service
 * on a loopback port that answers with canned sentences; the api-ssl checks
 * run against an `httpd` TLS server, since only the handshake matters there.
 */
use testing;
use task;
use httpd;

func hex(b as bytes) {
    return encoding.toText("hex", $b);
}

func testEncodeLenForms() {
    testing.assertEqual(hex(encodeLen(5)), "05");
    testing.assertEqual(hex(encodeLen(0)), "00");
    testing.assertEqual(hex(encodeLen(127)), "7f");
    testing.assertEqual(hex(encodeLen(128)), "8080");
    testing.assertEqual(hex(encodeLen(16383)), "bfff");
    testing.assertEqual(hex(encodeLen(16384)), "c04000");
    testing.assertEqual(hex(encodeLen(2097152)), "e0200000");
}

func testLenPrefixSize() {
    testing.assertEqual(lenPrefixSize(0x05), 1);
    testing.assertEqual(lenPrefixSize(0x80), 2);
    testing.assertEqual(lenPrefixSize(0xc0), 3);
    testing.assertEqual(lenPrefixSize(0xe0), 4);
    testing.assertEqual(lenPrefixSize(0xf0), 5);
}

func testDecodeLenRoundTrip() {
    def cases as list of int init [0, 5, 127, 128, 500, 16383, 16384, 2097152, 300000];
    for (def n in $cases) {
        testing.assertEqual(decodeLen(encodeLen($n), 0), $n);
    }
}

func testDecodeLenAtOffset() {
    # a 0xaa filler byte then encodeLen(128) = 8080
    def buf as bytes init encoding.fromText("hex", "aa8080");
    testing.assertEqual(decodeLen($buf, 1), 128);
}

func testParseFields() {
    def sentence as list of string init ["!re", "=name=ether1", "=type=ether", "=running=true"];
    def f as map of string to string init parseFields($sentence);
    testing.assertEqual($f["name"], "ether1");
    testing.assertEqual($f["type"], "ether");
    testing.assertEqual($f["running"], "true");
}

func testParseFieldsValueWithEquals() {
    # a value containing "=" keeps everything after the first "=" (comment=a=b)
    def f as map of string to string init parseFields(["!re", "=comment=a=b=c"]);
    testing.assertEqual($f["comment"], "a=b=c");
}

func testBuildWords() {
    def none as map of string to string init {};
    def noq as list of string init [];
    def w as list of string init buildWords("/interface/print", $none, $noq);
    testing.assertEqual(len($w), 1);
    testing.assertEqual($w[0], "/interface/print");

    def attrs as map of string to string init {};
    $attrs["address"] = "1.2.3.4/24";
    def withAttr as list of string init buildWords("/ip/address/add", $attrs, $noq);
    testing.assertEqual(len($withAttr), 2);
    testing.assertEqual($withAttr[1], "=address=1.2.3.4/24");
}

func testBuildWordsQueries() {
    # Query words are appended verbatim, after the command (and after any attrs).
    def none as map of string to string init {};
    def q as list of string init ["?type=ether", "?disabled"];
    def w as list of string init buildWords("/interface/print", $none, $q);
    testing.assertEqual(len($w), 3);
    testing.assertEqual($w[0], "/interface/print");
    testing.assertEqual($w[1], "?type=ether");
    testing.assertEqual($w[2], "?disabled");

    # Attribute words come before query words.
    def attrs as map of string to string init {};
    $attrs["numbers"] = "0";
    def wq as list of string init buildWords("/interface/print", $attrs, ["?type=ether"]);
    testing.assertEqual(len($wq), 3);
    testing.assertEqual($wq[1], "=numbers=0");
    testing.assertEqual($wq[2], "?type=ether");
}

# badQueryWord feeds buildWords a query word without its leading "?" - it must throw.
func badQueryWord() {
    def none as map of string to string init {};
    def bad as list of string init ["type=ether"];
    buildWords("/interface/print", $none, $bad);
}

func testBuildWordsRejectsBadQuery() {
    testing.assertThrows("badQueryWord", "mikrotik");
}

func testChallengeResponseShape() {
    # "00" + 32 hex chars of the MD5 digest = 34 characters, all lowercase hex.
    def r as string init challengeResponse("secret", "abcdef0123456789abcdef0123456789");
    testing.assertEqual(len($r), 34);
    testing.assertTrue(strings.startsWith($r, "00"));
}

# OM-004: a server-declared word length beyond the cap is rejected before it
# sizes a read, as the generic kind "limit".
func overWordCap() {
    checkWordLen(MAX_WORD_BYTES + 1);
}
func negWordCap() {
    checkWordLen(-1);
}
func testWordLenCap() {
    testing.assertThrows("overWordCap", "limit");
    testing.assertThrows("negWordCap", "mikrotik");
    checkWordLen(MAX_WORD_BYTES); # exactly at the limit does not throw
    checkWordLen(1);
}

# --- tagging + streaming (pure helpers) -------------------------------------

# A tagged command sentence carries a trailing `.tag=<id>` API word after the
# command (and any attribute words), so replies can be correlated.
func testBuildTaggedWords() {
    def none as map of string to string init {};
    def noq as list of string init [];
    def w as list of string init buildTaggedWords("/interface/monitor", $none, $noq, "7");
    testing.assertEqual(len($w), 2);
    testing.assertEqual($w[0], "/interface/monitor");
    testing.assertEqual($w[1], ".tag=7");

    # The tag word follows the attribute words.
    def attrs as map of string to string init {};
    $attrs["interface"] = "ether1";
    def wa as list of string init buildTaggedWords("/interface/monitor", $attrs, $noq, "abc");
    testing.assertEqual(len($wa), 3);
    testing.assertEqual($wa[0], "/interface/monitor");
    testing.assertEqual($wa[1], "=interface=ether1");
    testing.assertEqual($wa[2], ".tag=abc");
}

# parseTag reads the `.tag=` word back off a reply sentence; "" when absent.
func testParseTag() {
    def tagged as list of string init ["!re", ".tag=42", "=name=ether1", "=type=ether"];
    testing.assertEqual(parseTag($tagged), "42");

    def untagged as list of string init ["!re", "=name=ether1"];
    testing.assertEqual(parseTag($untagged), "");

    # `.tag` is distinct from the `=key=value` attribute words: parseFields does
    # not pick it up, and parseTag does not pick up a `=tag=` attribute.
    def f as map of string to string init parseFields($tagged);
    testing.assertTrue(not maps.has($f, "tag"));
    testing.assertEqual(parseTag(["!re", "=tag=99"]), "");
}

# buildCancelWords builds the `/cancel` sentence naming the tag to stop.
func testBuildCancelWords() {
    def w as list of string init buildCancelWords("42");
    testing.assertEqual(len($w), 2);
    testing.assertEqual($w[0], "/cancel");
    testing.assertEqual($w[1], "=tag=42");
}

# A tag round-trips: encode it into a sentence, read it back off the reply.
func testTagRoundTrip() {
    def none as map of string to string init {};
    def noq as list of string init [];
    def sent as list of string init buildTaggedWords("/ping", $none, $noq, "xyz");
    # The router echoes the tag on its reply; parseTag recovers it.
    def reply as list of string init ["!re", ".tag=xyz", "=host=1.2.3.4"];
    testing.assertEqual(parseTag($reply), parseTag($sent));
    testing.assertEqual(parseTag($sent), "xyz");
}

# --- connection options ------------------------------------------------------

func testOptionsPlainDefaults() {
    def o as Options init options("192.168.88.1", "admin", "secret");
    testing.assertEqual($o.host, "192.168.88.1");
    testing.assertEqual($o.user, "admin");
    testing.assertEqual($o.port, 8728);
    testing.assertFalse($o.tls);
}

# api-ssl moves the port and turns TLS on; the certificate checks are shown on
# a live socket below.
func testOptionsTLSDefaults() {
    def o as Options init optionsTLS("192.168.88.1", "admin", "secret");
    testing.assertEqual($o.port, 8729);
    testing.assertTrue($o.tls);
}

func testWithPortKeepsTransport() {
    def secure as Options init withPort(optionsTLS("10.0.0.1", "admin", "pw"), 18729);
    testing.assertEqual($secure.port, 18729);
    testing.assertTrue($secure.tls);

    def plain as Options init withPort(options("10.0.0.1", "admin", "pw"), 18728);
    testing.assertEqual($plain.port, 18728);
    testing.assertFalse($plain.tls);
}

func attrKeyWithEquals() {
    return buildWords("/ip/address/add", {"address=10.0.0.1/24": "x"}, []);
}
# An attribute name holding '=' is refused: RouterOS would read a different
# attribute.
func testAttrKeyValidated() {
    testing.assertThrows("attrKeyWithEquals", "mikrotik");
    testing.assertEqual(buildWords("/x", {"a": "b=c"}, []), ["/x", "=a=b=c"]);
}

# A !trap or !fatal reply is a MikrotikError with the reply, the category and
# the router's message; another failure has none.
func testRouterRepliesAreMikrotikErrors() {
    try {
        replyError("trap", {"category": "1", "message": "invalid value for argument address"});
        throw Error{kind: "missed", message: "a trap"};
    } catch (e) {
        testing.assertEqual($e.kind, "mikrotik");
        testing.assertEqual($e.reply, "trap");
        testing.assertEqual($e.category, "1");
        testing.assertEqual($e.routerMessage, "invalid value for argument address");
        testing.assertEqual($e.message, "mikrotik: !trap: invalid value for argument address");
    }
    try {
        replyError("fatal", {});
        throw Error{kind: "missed", message: "a fatal"};
    } catch (e) {
        testing.assertEqual($e.reply, "fatal");
        testing.assertEqual($e.routerMessage, "");
        testing.assertEqual($e.message, "mikrotik: !fatal: connection error");
    }
    try {
        fail("word length out of range: -1");
        throw Error{kind: "missed", message: "a local failure"};
    } catch (e) {
        testing.assertEqual($e.reply, "");
    }
}

# A router that closes the connection mid-sentence is kind "closed", not a
# MikrotikError.
func testAPeerCloseMidSentenceIsClosed() {
    def listener as net.Listener init net.listen("127.0.0.1:0");
    def server as task of null init spawn {
        def conn as net.Conn init net.accept($listener);
        net.writeBytes($conn, convert.bytesFromString("utf-8", "AB"));
        net.close($conn);
    };
    def c as net.Conn init net.connect(net.address($listener));
    try {
        readN($c, 8);
        throw Error{kind: "missed", message: "a close mid-sentence"};
    } catch (e) {
        testing.assertEqual($e.kind, "closed");
    }
    task.wait($server);
    net.close($c);
    net.close($listener);
}

# --- a fake RouterOS API service ---------------------------------------------

# A private CA and a certificate it signed for 127.0.0.1 (EC P-256, valid
# until 2126), made with openssl apart from the deck.
def const TEST_CA as string init '-----BEGIN CERTIFICATE-----
MIIBeDCCAR6gAwIBAgIUOCAXCd5fXKjpkQhIBbaIeP01AgAwCgYIKoZIzj0EAwIw
ITEfMB0GA1UEAwwWamVubmlmZXIgb2F1dGggdGVzdCBDQTAgFw0yNjExMTMxOTQ5
NTJaGA8yMTI2MTAyMDE5NDk1MlowITEfMB0GA1UEAwwWamVubmlmZXIgb2F1dGgg
dGVzdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGQvmpaLOv9CGLE1Ilek
2V5XnOFNMwiBgZI09oYoS+WYlGtAB1dEOpxWwcnUEiF86AtiZ/uF8D0WFgezR57O
TEajMjAwMB0GA1UdDgQWBBR/0y8Q0tMNGRpKU7WXlKjv/XFX9TAPBgNVHRMBAf8E
BTADAQH/MAoGCCqGSM49BAMCA0gAMEUCID8BnkmGr+XWubXAa/9qbCa2X5QPYc25
EIDw/zQbMRODAiEAoDASeYeer2KQ+nQSgVDz3TBQryeY/UFDlTBxWexrO3M=
-----END CERTIFICATE-----
';
def const TEST_LEAF as string init '-----BEGIN CERTIFICATE-----
MIIBbDCCARKgAwIBAgIUQgPoiSZcpEV2h/SJCowHnZ0UC90wCgYIKoZIzj0EAwIw
ITEfMB0GA1UEAwwWamVubmlmZXIgb2F1dGggdGVzdCBDQTAgFw0yNjExMTMxOTQ5
NTJaGA8yMTI2MTAyMDE5NDk1MlowFDESMBAGA1UEAwwJMTI3LjAuMC4xMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAE7SaWL/z/vlLLCG2AVE1IiinsofwT3tS0DgMv
jIBNpZ5PDjwKfykNKHkZKfKush1JwRQejYx55AFOBQ78uAbubqMzMDEwDwYDVR0R
BAgwBocEfwAAATAJBgNVHRMEAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAoGCCqG
SM49BAMCA0gAMEUCIQD4nl9MEMwGys5vlzHn+7fRDJJ83emraZCEvU8Th/4KRwIg
MQNHaof4BWJUNUrb2IK41cgpDmUkoOZc81C88SXnpvs=
-----END CERTIFICATE-----
';
def const TEST_LEAF_KEY as string init '-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghGp3k75AJPnKjPGA
HjIKGY1NAoZnrQpZgvnv8XQalZahRANCAATtJpYv/P++UssIbYBUTUiKKeyh/BPe
1LQOAy+MgE2lnk8OPAp/KQ0oeRkp8q6yHUnBFB6NjHnkAU4FDvy4Bu5u
-----END PRIVATE KEY-----
';

# The challenge an old (pre-6.43) router sends, and the response to it for the
# password "pw": "00" + hex(MD5(0x00 + "pw" + challenge)), computed apart from
# the deck.
def const OLD_CHALLENGE as string init "0123456789abcdef0123456789abcdef";
def const OLD_RESPONSE as string init "00bb1a106c7a9fbf707247b06d10551cea";

func fieldOf(sentence as list of string, key as string) {
    def f as map of string to string init parseFields($sentence);
    if (maps.has($f, $key)) {
        return $f[$key];
    }
    return "";
}

func tagWordOf(sentence as list of string) {
    return ".tag=" + parseTag($sentence);
}

func hasWord(sentence as list of string, word as string) {
    for (def w in $sentence) {
        if ($w == $word) {
            return true;
        }
    }
    return false;
}

# writeTagged writes a reply sentence, with a `.tag=` word when the command
# carried a tag.
func writeTagged(conn as net.Conn, words as list of string, tag as string) {
    def out as list of string init [];
    for (def w in $words) {
        $out[] = $w;
    }
    if ($tag != "") {
        $out[] = ".tag=" + $tag;
    }
    writeSentence($conn, $out);
    return;
}

# answer replies to one command sentence the way a router does.
func answer(conn as net.Conn, cmd as list of string) {
    def name as string init $cmd[0];
    if ($name == "/cancel") {
        def tw as string init ".tag=" + fieldOf($cmd, "tag");
        writeSentence($conn, ["!trap", "=category=2", "=message=interrupted", $tw]);
        writeSentence($conn, ["!done", $tw]);
        writeSentence($conn, ["!done"]);
    } elseif ($name == "/interface/monitor") {
        def tw as string init tagWordOf($cmd);
        writeSentence($conn, ["!re", "=name=ether1", "=rx=100", $tw]);
        writeSentence($conn, ["!re", "=name=ether1", "=rx=200", $tw]);
    } elseif ($name == "/interface/print") {
        def tag as string init parseTag($cmd);
        writeTagged($conn, ["!re", "=name=ether1", "=type=ether", "=running=true"], $tag);
        if (not hasWord($cmd, "?running=true")) {
            writeTagged($conn, ["!re", "=name=ether2", "=type=ether", "=running=false"], $tag);
        }
        writeTagged($conn, ["!done"], $tag);
    } elseif ($name == "/ip/address/add") {
        writeSentence($conn, ["!done", "=ret=*" + fieldOf($cmd, "interface")]);
    } elseif ($name == "/system/reboot") {
        writeSentence($conn, ["!fatal", "=message=rebooting"]);
    } elseif ($name == "/huge") {
        # a 5-byte length prefix declaring a word of 2^31 bytes
        net.writeBytes($conn, encoding.fromText("hex", "f080000000"));
    } else {
        writeSentence($conn, ["!trap", "=category=0", "=message=no such command"]);
        writeSentence($conn, ["!done"]);
    }
    return;
}

# answerLogin answers the login sentences: a plaintext login, or with `old` the
# pre-6.43 challenge first. Returns whether the client logged in.
func answerLogin(conn as net.Conn, old as bool) {
    def first as list of string init readSentence($conn);
    testing.assertEqual($first[0], "/login");
    testing.assertEqual(fieldOf($first, "name"), "admin");
    if ($old) {
        writeSentence($conn, ["!done", "=ret=" + OLD_CHALLENGE]);
        def second as list of string init readSentence($conn);
        testing.assertEqual($second[0], "/login");
        testing.assertEqual(fieldOf($second, "response"), OLD_RESPONSE);
        writeSentence($conn, ["!done"]);
        return true;
    }
    if (fieldOf($first, "password") != "pw") {
        writeSentence($conn, ["!trap", "=message=invalid user name or password (6)"]);
        writeSentence($conn, ["!done"]);
        return false;
    }
    writeSentence($conn, ["!done"]);
    return true;
}

# fakeRouter serves one client on `listener` until it closes the connection,
# and returns the command sentences it received.
func fakeRouter(listener as net.Listener, old as bool) {
    def conn as net.Conn init net.accept($listener);
    defer net.close($conn);
    def seen as list of list of string init [];
    if (not answerLogin($conn, $old)) {
        return $seen;
    }
    while (true) {
        def cmd as list of string init [];
        try {
            $cmd = readSentence($conn);
        } catch (e) {
            # the client closed; with replies it never read (the /cancel's
            # own !done), its close arrives as a reset
            if ($e.kind == "closed" or $e.kind == "net") {
                return $seen;
            }
            throw $e;
        }
        $seen[] = $cmd;
        answer($conn, $cmd);
    }
}

func localOptions(listener as net.Listener, password as string) {
    def port as string init strings.split(net.address($listener), ":")[1];
    return withPort(options("127.0.0.1", "admin", $password), convert.toInt($port));
}

func testTalkPrintRunAndTrap() {
    def listener as net.Listener init net.listen("127.0.0.1:0");
    defer net.close($listener);
    def router as task of list of list of string init spawn {
        return fakeRouter($listener, false);
    };
    def s as Session init connect(localOptions($listener, "pw"));

    def rows as list of map of string to string init print($s, "/interface");
    testing.assertEqual(len($rows), 2);
    testing.assertEqual($rows[0]["name"], "ether1");
    testing.assertEqual($rows[1]["running"], "false");

    def some as list of map of string to string init printWhere(
        $s,
        "/interface",
        ["?running=true"]);
    testing.assertEqual(len($some), 1);
    testing.assertEqual(len(talk($s, "/interface/print", {})), 2);
    testing.assertEqual(
        len(talkQuery($s, "/interface/print", {".proplist": "name"}, ["?running=true"])),
        1);

    testing.assertEqual(
        run($s, "/ip/address/add", {"address": "10.0.0.1/24", "interface": "9"}),
        "*9");

    try {
        talk($s, "/bad/command", {});
        throw Error{kind: "missed", message: "a trap"};
    } catch (e) {
        testing.assertEqual($e.kind, "mikrotik");
        def me as MikrotikError init $e;
        testing.assertEqual($me.reply, "trap");
        testing.assertEqual($me.category, "0");
        testing.assertEqual($me.routerMessage, "no such command");
    }
    # the session survives a trap
    testing.assertEqual(len(print($s, "/interface")), 2);
    close($s);

    def seen as list of list of string init task.wait($router);
    testing.assertEqual($seen[3], ["/interface/print", "=.proplist=name", "?running=true"]);
}

func testOldRouterChallengeLogin() {
    def listener as net.Listener init net.listen("127.0.0.1:0");
    defer net.close($listener);
    def router as task of list of list of string init spawn {
        return fakeRouter($listener, true);
    };
    def s as Session init connect(localOptions($listener, "pw"));
    testing.assertEqual(len(print($s, "/interface")), 2);
    close($s);
    task.wait($router);
}

func testRefusedLoginIsAMikrotikError() {
    def listener as net.Listener init net.listen("127.0.0.1:0");
    defer net.close($listener);
    def router as task of list of list of string init spawn {
        return fakeRouter($listener, false);
    };
    try {
        connect(localOptions($listener, "wrong"));
        throw Error{kind: "missed", message: "a refused login"};
    } catch (e) {
        testing.assertEqual($e.kind, "mikrotik");
        testing.assertEqual($e.message, "mikrotik: !trap: invalid user name or password (6)");
    }
    task.wait($router);
}

func testFatalReplyIsAMikrotikError() {
    def listener as net.Listener init net.listen("127.0.0.1:0");
    defer net.close($listener);
    def router as task of list of list of string init spawn {
        return fakeRouter($listener, false);
    };
    def s as Session init connect(localOptions($listener, "pw"));
    try {
        run($s, "/system/reboot", {});
        throw Error{kind: "missed", message: "a fatal"};
    } catch (e) {
        testing.assertEqual($e.kind, "mikrotik");
        def me as MikrotikError init $e;
        testing.assertEqual($me.reply, "fatal");
        testing.assertEqual($me.routerMessage, "rebooting");
    }
    close($s);
    task.wait($router);
}

func testAWordOverTheCapIsLimit() {
    def listener as net.Listener init net.listen("127.0.0.1:0");
    defer net.close($listener);
    def router as task of list of list of string init spawn {
        return fakeRouter($listener, false);
    };
    def s as Session init connect(localOptions($listener, "pw"));
    try {
        talk($s, "/huge", {});
        throw Error{kind: "missed", message: "a word over the cap"};
    } catch (e) {
        testing.assertEqual($e.kind, "limit");
    }
    close($s);
    task.wait($router);
}

func testTaggedCommandAndStream() {
    def listener as net.Listener init net.listen("127.0.0.1:0");
    defer net.close($listener);
    def router as task of list of list of string init spawn {
        return fakeRouter($listener, false);
    };
    def s as Session init connect(localOptions($listener, "pw"));

    testing.assertEqual(len(talkTagged($s, "/interface/print", {}, "t1")), 2);
    testing.assertEqual(len(talkTagged($s, "/interface/print", {}, "")), 2);

    def tag as string init listen($s, "/interface/monitor", {"interface": "ether1"});
    testing.assertTrue(len($tag) > 0);
    testing.assertEqual(receiveReply($s, $tag)["rx"], "100");
    testing.assertEqual(receiveReply($s, $tag)["rx"], "200");
    cancel($s, $tag);
    # the interrupted trap (category 2) and the tagged !done end the stream
    testing.assertEqual(len(receiveReply($s, $tag)), 0);
    close($s);

    def seen as list of list of string init task.wait($router);
    testing.assertEqual($seen[0], ["/interface/print", ".tag=t1"]);
    testing.assertEqual($seen[3], ["/cancel", "=tag=" + $tag]);
}

func testARefusedConnectionIsANetError() {
    def listener as net.Listener init net.listen("127.0.0.1:0");
    def o as Options init localOptions($listener, "pw");
    net.close($listener);
    try {
        connect($o);
        throw Error{kind: "missed", message: "a refused connection"};
    } catch (e) {
        testing.assertEqual($e.kind, "net");
        def ne as net.NetError init $e;
        testing.assertEqual($ne.op, "connect");
        testing.assertEqual($ne.reason, "refused");
    }
}

# tlsLogin connects with api-ssl options to `srv`, an HTTPS server, and returns
# the kind of the error the login ends in: past the handshake, the server's
# HTTP answer is no RouterOS reply. The password ends the login sentence's
# bytes with an empty line, so the server answers 400 and closes at once
# instead of waiting for the rest of a request.
func tlsLogin(srv as httpd.Server, o as Options) {
    def port as string init strings.split(httpd.address($srv), ":")[1];
    try {
        connect(withPort($o, convert.toInt($port)));
    } catch (e) {
        if ($e.kind == "net") {
            def ne as net.NetError init $e;
            return "net/" + $ne.reason;
        }
        return $e.kind;
    }
    return "logged in";
}

func testApiSslVerifiesTheCertificate() {
    def srv as httpd.Server init httpd.listenTLS(
        "127.0.0.1:0",
        convert.bytesFromString("utf-8", TEST_LEAF),
        convert.bytesFromString("utf-8", TEST_LEAF_KEY));
    defer httpd.shutdown($srv);
    def base as Options init optionsTLS("127.0.0.1", "admin", "pw\r\n\r\n");
    # the system roots lack the test CA
    testing.assertEqual(tlsLogin($srv, $base), "net/tls");
    # pinned or unchecked, the handshake succeeds and the login fails on the
    # HTTP answer (a close or a reset, depending on timing)
    def pem as bytes init convert.bytesFromString("utf-8", TEST_CA);
    def pinned as string init tlsLogin($srv, withCA($base, $pem));
    testing.assertTrue($pinned != "net/tls" and $pinned != "logged in");
    def any as string init tlsLogin($srv, insecure($base));
    testing.assertTrue($any != "net/tls" and $any != "logged in");
}
