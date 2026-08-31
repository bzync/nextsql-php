<?php

declare(strict_types=1);

require dirname(__DIR__) . '/autoload.php';

use NextSQL\Client;
use NextSQL\Exception;
use NextSQL\Protocol;

function fail(string $msg): never
{
    fwrite(STDERR, $msg . "\n");
    exit(1);
}

function expectException(callable $fn, string $code): void
{
    try {
        $fn();
        fail('expected exception ' . $code);
    } catch (Exception $e) {
        if ($e->errorCode !== $code) {
            fail('got ' . $e->errorCode . ' want ' . $code);
        }
    }
}

expectException(static function (): void {
    Client::validateConfig([
        'address' => 'nextsql://app:secret@db.example.com:7210/prod?key=deadbeef',
        'user' => 'app',
        'password' => 'x',
        'tls' => [],
    ]);
}, 'invalid_argument');

expectException(static function (): void {
    Client::validateConfig([
        'address' => 'db.example.com:7210',
        'user' => 'app',
        'insecureNoTLS' => true,
    ]);
}, 'invalid_argument');

Client::validateConfig([
    'address' => '127.0.0.1:7210',
    'user' => 'app',
    'insecureNoTLS' => true,
]);

if (!Client::isLoopback('127.0.0.1:7210') || Client::isLoopback('db.example.com:7210')) {
    fail('loopback');
}

$s = Protocol::encodeParam('hello');
$d = Protocol::decodeValue($s, 0);
if ($d['value'] !== 'hello' || $d['kind'] !== Client::KIND_STRING) {
    fail('string param');
}
$b = Protocol::encodeParam(true);
if (Protocol::decodeValue($b, 0)['value'] !== true) {
    fail('bool param');
}
$n = Protocol::encodeParam(null);
if (Protocol::decodeValue($n, 0)['value'] !== null) {
    fail('null param');
}

$body = Protocol::encodeDecimal('-12.50');
$raw = substr($body, 4);
if (Protocol::decodeDecimal($raw) !== '-12.50') {
    fail('decimal ' . Protocol::decodeDecimal($raw));
}

if (Protocol::decodeNSJB("NSJB\x01\x02") !== true) {
    fail('nsjb true');
}
if (Protocol::decodeNSJB("NSJB\x01\x00") !== null) {
    fail('nsjb null');
}

$pt = Protocol::encodeParam(['lon' => -73.98, 'lat' => 40.75]);
$got = Protocol::decodeValue($pt, 0);
if ($got['kind'] !== Client::KIND_POINT || abs($got['value']['lon'] + 73.98) > 1e-9) {
    fail('point');
}

// Follower-read routing classifiers.
foreach (['SELECT 1', '  select n from t', "\n-- c\nSELECT n FROM t", 'SHOW TASKS', 'WITH c AS (SELECT n FROM t) SELECT n FROM c'] as $s) {
    if (!Client::isReadOnlySQL($s)) {
        fail('expected read-only: ' . $s);
    }
}
foreach (["INSERT INTO t (n) VALUES ('x')", 'UPDATE t SET n = 1', 'DELETE FROM t', "UPSERT INTO t (id) VALUES ('x')", 'EXPLAIN ANALYZE SELECT n FROM t', 'BEGIN'] as $s) {
    if (Client::isReadOnlySQL($s)) {
        fail('expected not read-only: ' . $s);
    }
}
$tc = Client::txnControl('  begin transaction ');
if (!$tc['begin'] || $tc['end']) {
    fail('txnControl begin');
}
$tc = Client::txnControl('ROLLBACK');
if ($tc['begin'] || !$tc['end']) {
    fail('txnControl rollback');
}

// SetReadConsistency wire encoding.
$src = Protocol::encodeSetReadConsistency(Client::READ_BOUNDED, 2500);
if (strlen($src) !== 9 || ord($src[0]) !== 1) {
    fail('set-read-consistency header');
}
if (unpack('V', substr($src, 1, 4))[1] !== 2500) {
    fail('set-read-consistency ms');
}
expectException(static function (): void {
    Protocol::encodeSetReadConsistency(9, 0);
}, 'invalid_argument');

// NodeStatus round-trips the server encoding: u16 role, flags byte, 3x u64.
$role = 'follower';
$buf = pack('v', strlen($role)) . $role
    . chr(0x02)
    . pack('V', 4242) . pack('V', 0)
    . pack('V', 0xFFFFFFFF) . pack('V', 0xFFFFFFFF)
    . pack('V', 7) . pack('V', 0);
$st = Protocol::decodeNodeStatus($buf);
if ($st['role'] !== 'follower' || $st['hasLeader'] !== false || $st['healthy'] !== true) {
    fail('node status flags');
}
if ($st['appliedLSN'] !== 4242 || $st['lastContactMs'] !== -1 || $st['applyBacklog'] !== 7) {
    fail('node status fields ' . json_encode($st));
}
expectException(static function () use ($buf): void {
    Protocol::decodeNodeStatus(substr($buf, 0, strlen($buf) - 1));
}, 'protocol');

expectException(static function (): void {
    \NextSQL\Cluster::connect(['user' => 'app', 'tls' => []]);
}, 'invalid_argument');

fwrite(STDOUT, "ok\n");
