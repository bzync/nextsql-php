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

fwrite(STDOUT, "ok\n");
