<?php

declare(strict_types=1);

require dirname(__DIR__) . '/autoload.php';

use NextSQL\Client;
use NextSQL\Exception;
use NextSQL\FieldEncryption;
use NextSQL\FieldType;
use NextSQL\FileFieldKeyring;
use NextSQL\MemoryFieldKeyring;
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

function fieldKey(string $id, int $fill): array
{
    return ['id' => $id, 'material' => str_repeat(chr($fill), 32)];
}

$v1 = fieldKey('v1', 1);
$ring = new MemoryFieldKeyring($v1);
$values = [
    [FieldType::uuid(), '00112233-4455-6677-8899-aabbccddeeff'],
    [FieldType::string(), 'secret'],
    [FieldType::text(), 'long secret'],
    [FieldType::decimal(8, 2), '-12.50'],
    [FieldType::timestampTZ(), new DateTimeImmutable('2026-09-01T01:02:03.123456Z')],
    [FieldType::json(), ['z' => [true, null], 'a' => 7]],
    [FieldType::bool(), true],
    [FieldType::blob(), "\x00\xff\xde\xad\xbe\xef"],
    [FieldType::int8(), -128],
    [FieldType::int8(), 127],
    [FieldType::int16(), -32768],
    [FieldType::int32(), -2147483648],
    [FieldType::int64(), PHP_INT_MIN],
    [FieldType::int64(), PHP_INT_MAX],
    [FieldType::uint8(), 255],
    [FieldType::uint16(), 65535],
    [FieldType::uint32(), 4294967295],
    [FieldType::uint64(), PHP_INT_MAX],
    [FieldType::uint64(), '18446744073709551615'],
];
foreach ($values as [$type, $value]) {
    $sealed = FieldEncryption::encrypt($ring, 'app', 'accounts', 'secret', $type, $value);
    if (!is_string($sealed) || !str_starts_with($sealed, 'NSCE1.')) {
        fail('field encryption prefix');
    }
    $plain = FieldEncryption::decrypt($ring, 'app', 'accounts', 'secret', $type, $sealed);
    if ($value instanceof DateTimeInterface) {
        if (!$plain instanceof DateTimeInterface || $plain->format('U.u') !== $value->format('U.u')) {
            fail('field timestamp round trip');
        }
    } elseif ($type['kind'] === Client::KIND_JSON ? $plain != $value : $plain !== $value) {
        fail('field round trip ' . json_encode($type));
    }
}
$old = FieldEncryption::encrypt($ring, 'app', 'accounts', 'secret', FieldType::text(), 'old');
$again = FieldEncryption::encrypt($ring, 'app', 'accounts', 'secret', FieldType::text(), 'old');
if ($old === $again) {
    fail('field encryption is not randomized');
}
$decimal = FieldEncryption::encrypt($ring, 'app', 'accounts', 'amount', FieldType::decimal(4, 2), '1');
if (FieldEncryption::decrypt($ring, 'app', 'accounts', 'amount', FieldType::decimal(4, 2), $decimal) !== '1.00') {
    fail('field decimal rescale');
}
expectException(static function () use ($ring): void {
    FieldEncryption::encrypt($ring, 'app', 'accounts', 'amount', FieldType::decimal(4, 2), '123.45');
}, 'invalid_argument');
$ring->rotate(fieldKey('v2', 2));
if (FieldEncryption::decrypt($ring, 'app', 'accounts', 'secret', FieldType::text(), $old) !== 'old') {
    fail('field overlap decrypt');
}
expectException(static function () use ($ring, $old): void {
    FieldEncryption::decrypt($ring, 'app', 'accounts', 'other', FieldType::text(), $old);
}, 'crypto');
expectException(static function () use ($ring): void {
    FieldEncryption::encrypt($ring, 'app', 'accounts', 'secret', FieldType::text(), str_repeat('x', 1 << 20));
}, 'exhausted');
$ring->revoke('v1');
expectException(static function () use ($ring, $old): void {
    FieldEncryption::decrypt($ring, 'app', 'accounts', 'secret', FieldType::text(), $old);
}, 'crypto');
$goCiphertext = 'NSCE1.AQECdjEDAAAAAABEeyxf_quGP5And9z0FmNijEp3uSiDspby_y1zIxe9L1R-llGtWQxh';
if (FieldEncryption::decrypt(new MemoryFieldKeyring($v1), 'app', 'accounts', 'secret', FieldType::text(), $goCiphertext) !== 'portable') {
    fail('Go ciphertext portability');
}

$fkDir = sys_get_temp_dir() . '/nextsql-fk-' . bin2hex(random_bytes(8));
mkdir($fkDir);
$fkPath = $fkDir . '/keyring.nsfk';
$fkr = FileFieldKeyring::create($fkPath, fieldKey('v1', 1));
$fkOld = FieldEncryption::encrypt($fkr, 'app', 'accounts', 'secret', FieldType::text(), 'old');

expectException(static function () use ($fkPath): void {
    FileFieldKeyring::create($fkPath, fieldKey('v2', 2));
}, 'already_exists');

$fkr->rotate(fieldKey('v2', 2));
$fkAfterRotate = FileFieldKeyring::open($fkPath);
if (FieldEncryption::decrypt($fkAfterRotate, 'app', 'accounts', 'secret', FieldType::text(), $fkOld) !== 'old') {
    fail('FileFieldKeyring overlap decrypt after reopen');
}
$fkFresh = FieldEncryption::encrypt($fkAfterRotate, 'app', 'accounts', 'secret', FieldType::text(), 'new');

$fkr->revoke('v1');
$fkAfterRevoke = FileFieldKeyring::open($fkPath);
expectException(static function () use ($fkAfterRevoke, $fkOld): void {
    FieldEncryption::decrypt($fkAfterRevoke, 'app', 'accounts', 'secret', FieldType::text(), $fkOld);
}, 'crypto');
if (FieldEncryption::decrypt($fkAfterRevoke, 'app', 'accounts', 'secret', FieldType::text(), $fkFresh) !== 'new') {
    fail('FileFieldKeyring current key after reopen');
}
$fkList = $fkAfterRevoke->list();
$fkByID = [];
foreach ($fkList as $entry) {
    $fkByID[$entry['id']] = $entry;
}
if ($fkByID['v1']['current'] !== false || $fkByID['v1']['revoked'] !== true) {
    fail('FileFieldKeyring v1 not revoked on disk');
}
if ($fkByID['v2']['current'] !== true || $fkByID['v2']['revoked'] !== false) {
    fail('FileFieldKeyring v2 not current on disk');
}

expectException(static function () use ($fkr): void {
    $fkr->revoke('v2');
}, 'conflict');
expectException(static function () use ($fkr): void {
    $fkr->rotate(fieldKey('v1', 9));
}, 'conflict');

$fkRaw = file_get_contents($fkPath);
file_put_contents($fkPath, 'not a keyring');
expectException(static function () use ($fkr): void {
    $fkr->reload();
}, 'invalid_format');
if ($fkr->currentFieldKey('app', 'accounts', 'secret')['id'] !== 'v2') {
    fail('FileFieldKeyring in-memory state should survive a failed reload');
}
file_put_contents($fkPath, $fkRaw);

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

// PHP strings are byte-safe, so a BLOB parameter needs the explicit
// ['kind' => 'blob', 'value' => ...] wrapper to disambiguate from STRING.
$rawBlob = "\x00\xff\xfe\x00\xde\xad\xbe\xef";
$bl = Protocol::encodeParam(['kind' => 'blob', 'value' => $rawBlob]);
$gotBlob = Protocol::decodeValue($bl, 0);
if ($gotBlob['kind'] !== Client::KIND_BLOB || $gotBlob['value'] !== $rawBlob) {
    fail('blob param');
}
$emptyBlob = Protocol::decodeValue(Protocol::encodeParam(['kind' => 'blob', 'value' => '']), 0);
if ($emptyBlob['kind'] !== Client::KIND_BLOB || $emptyBlob['value'] !== '') {
    fail('empty blob param');
}

// D2 (Datatype expansion track): fixed-width int params, both boundary
// values and overflow rejection. A bare PHP int still defaults to
// KIND_DECIMAL (the server coerces it into any numeric column).
$intCases = [
    ['int8', -128, Client::KIND_INT8],
    ['int8', 127, Client::KIND_INT8],
    ['int16', -32768, Client::KIND_INT16],
    ['int16', 32767, Client::KIND_INT16],
    ['int32', -2147483648, Client::KIND_INT32],
    ['int32', 2147483647, Client::KIND_INT32],
    ['int64', PHP_INT_MIN, Client::KIND_INT64],
    ['int64', PHP_INT_MAX, Client::KIND_INT64],
];
foreach ($intCases as [$which, $value, $kind]) {
    $got = Protocol::decodeValue(Protocol::encodeParam(['kind' => $which, 'value' => $value]), 0);
    if ($got['kind'] !== $kind || $got['value'] !== $value) {
        fail("int param $which $value -> " . var_export($got, true));
    }
}
try {
    Protocol::encodeParam(['kind' => 'int8', 'value' => 128]);
    fail('expected 128 to overflow int8');
} catch (Exception $e) {
    // expected
}
try {
    Protocol::encodeParam(['kind' => 'int8', 'value' => -129]);
    fail('expected -129 to overflow int8');
} catch (Exception $e) {
    // expected
}
$bareInt = Protocol::decodeValue(Protocol::encodeParam(42), 0);
if ($bareInt['kind'] !== Client::KIND_DECIMAL) {
    fail('bare int param should default to KIND_DECIMAL');
}

// D3 (Datatype expansion track): fixed-width uint params. UINT64 additionally
// accepts a decimal digit string above PHP_INT_MAX, since PHP has no
// unsigned 64-bit type, and decodes the same way when it must.
$uintCases = [
    ['uint8', 0, Client::KIND_UINT8],
    ['uint8', 255, Client::KIND_UINT8],
    ['uint16', 0, Client::KIND_UINT16],
    ['uint16', 65535, Client::KIND_UINT16],
    ['uint32', 0, Client::KIND_UINT32],
    ['uint32', 4294967295, Client::KIND_UINT32],
    ['uint64', 0, Client::KIND_UINT64],
    ['uint64', PHP_INT_MAX, Client::KIND_UINT64],
];
foreach ($uintCases as [$which, $value, $kind]) {
    $got = Protocol::decodeValue(Protocol::encodeParam(['kind' => $which, 'value' => $value]), 0);
    if ($got['kind'] !== $kind || $got['value'] !== $value) {
        fail("uint param $which $value -> " . var_export($got, true));
    }
}
// A magnitude above PHP_INT_MAX round-trips as a decimal string.
$bigUint = Protocol::decodeValue(Protocol::encodeParam(['kind' => 'uint64', 'value' => '18446744073709551615']), 0);
if ($bigUint['kind'] !== Client::KIND_UINT64 || $bigUint['value'] !== '18446744073709551615') {
    fail('uint64 above PHP_INT_MAX -> ' . var_export($bigUint, true));
}
try {
    Protocol::encodeParam(['kind' => 'uint8', 'value' => 256]);
    fail('expected 256 to overflow uint8');
} catch (Exception $e) {
    // expected
}
try {
    Protocol::encodeParam(['kind' => 'uint8', 'value' => -1]);
    fail('expected -1 to be rejected for uint8');
} catch (Exception $e) {
    // expected
}
try {
    Protocol::encodeParam(['kind' => 'uint64', 'value' => '18446744073709551616']);
    fail('expected 2^64 to overflow uint64');
} catch (Exception $e) {
    // expected
}

// D11 (Datatype expansion track): ENUM params carry their declared label
// list alongside the value (docs/design-datatypes.md D11).
$enumLabels = ['small', 'medium', 'large'];
$enumGot = Protocol::decodeValue(Protocol::encodeParam(['kind' => 'enum', 'value' => 'medium', 'labels' => $enumLabels]), 0);
if ($enumGot['kind'] !== Client::KIND_ENUM || $enumGot['value'] !== 'medium' || $enumGot['labels'] !== $enumLabels) {
    fail('enum param -> ' . var_export($enumGot, true));
}
try {
    Protocol::encodeParam(['kind' => 'enum', 'value' => 'huge', 'labels' => $enumLabels]);
    fail('expected a non-member ENUM label to be rejected');
} catch (Exception $e) {
    // expected
}
// decodeRowDesc parses the same label-list framing for a column header.
$rowDesc = "\x01\x00" . Protocol::u16str('sz') . chr(Client::KIND_ENUM) . str_repeat("\x00", 5) . Protocol::appendEnumLabels($enumLabels);
$cols = Protocol::decodeRowDesc($rowDesc);
if (count($cols) !== 1 || $cols[0]['kind'] !== Client::KIND_ENUM || $cols[0]['labels'] !== $enumLabels) {
    fail('enum row desc -> ' . var_export($cols, true));
}

// D5/D7/D8 (Datatype expansion track): DATE, TIME, naive TIMESTAMP,
// FLOAT32/FLOAT64 param round-trip, including two real bugs found and
// fixed while implementing this: negative-nanosecond TIMESTAMPTZ encode
// (u64fromDec mistreated a leading '-' as digit 0) and decode (intdiv's
// truncation-toward-zero + PHP's dividend-signed % produced a negative
// usec, so DateTimeImmutable::createFromFormat silently returned false).
$preEpoch = new DateTimeImmutable('1969-12-31T23:59:59.500000Z');
$gotPre = Protocol::decodeValue(Protocol::encodeParam($preEpoch), 0);
if ($gotPre['value'] === false || $gotPre['value']->format('Y-m-d H:i:s.u') !== '1969-12-31 23:59:59.500000') {
    fail('pre-1970 TIMESTAMPTZ round trip -> ' . var_export($gotPre['value'], true));
}

$dateVal = new DateTimeImmutable('2024-01-15T00:00:00Z');
$gotDate = Protocol::decodeValue(Protocol::encodeParam(['kind' => 'date', 'value' => $dateVal]), 0);
if ($gotDate['kind'] !== Client::KIND_DATE || $gotDate['value']->format('Y-m-d') !== '2024-01-15') {
    fail('date round trip -> ' . var_export($gotDate, true));
}
$datePreEpoch = new DateTimeImmutable('1969-12-31T00:00:00Z');
$gotDatePre = Protocol::decodeValue(Protocol::encodeParam(['kind' => 'date', 'value' => $datePreEpoch]), 0);
if ($gotDatePre['value']->format('Y-m-d') !== '1969-12-31') {
    fail('pre-1970 date round trip -> ' . var_export($gotDatePre['value'], true));
}

$nsInDay = (23 * 3600 + 59 * 60 + 59) * 1_000_000_000 + 999_000_000;
$gotTime = Protocol::decodeValue(Protocol::encodeParam(['kind' => 'time', 'value' => $nsInDay]), 0);
if ($gotTime['kind'] !== Client::KIND_TIME || $gotTime['value'] !== $nsInDay) {
    fail('time round trip -> ' . var_export($gotTime, true));
}

$naiveTs = new DateTimeImmutable('2024-06-15T10:30:00Z');
$gotNaive = Protocol::decodeValue(Protocol::encodeParam(['kind' => 'timestamp', 'value' => $naiveTs]), 0);
if ($gotNaive['kind'] !== Client::KIND_TIMESTAMP || $gotNaive['value']->format('Y-m-d H:i:s') !== '2024-06-15 10:30:00') {
    fail('naive timestamp round trip -> ' . var_export($gotNaive, true));
}
// A bare DateTimeInterface still defaults to TIMESTAMPTZ.
if (Protocol::decodeValue(Protocol::encodeParam($naiveTs), 0)['kind'] !== Client::KIND_TIMESTAMPTZ) {
    fail('bare DateTimeInterface should default to TIMESTAMPTZ');
}

foreach (['float32' => Client::KIND_FLOAT32, 'float64' => Client::KIND_FLOAT64] as $which => $wantKind) {
    $got = Protocol::decodeValue(Protocol::encodeParam(['kind' => $which, 'value' => 1.5]), 0);
    if ($got['kind'] !== $wantKind || $got['value'] !== 1.5) {
        fail("$which round trip -> " . var_export($got, true));
    }
    // NaN/Infinity are valid FLOAT values (unlike the bare-number -> Decimal path).
    $gotNan = Protocol::decodeValue(Protocol::encodeParam(['kind' => $which, 'value' => NAN]), 0);
    if (!is_nan($gotNan['value'])) {
        fail("$which NaN round trip -> " . var_export($gotNan, true));
    }
    $gotInf = Protocol::decodeValue(Protocol::encodeParam(['kind' => $which, 'value' => INF]), 0);
    if ($gotInf['value'] !== INF) {
        fail("$which Infinity round trip -> " . var_export($gotInf, true));
    }
}

// CHAR/VARCHAR decode as plain strings (a client-side write goes through
// plain STRING/TEXT, server-coerced — no encode wrapper needed).
$charRaw = chr(Client::KIND_CHAR) . "\x00" . str_repeat("\x00", 5) . pack('V', 5) . 'ab   ';
$gotChar = Protocol::decodeValue($charRaw, 0);
if ($gotChar['value'] !== 'ab   ') {
    fail('char decode -> ' . var_export($gotChar, true));
}

// D6 (Datatype expansion track): INTERVAL param round-trip, including a
// negative nanos component (uses the same i64le encode/splitNanos-adjacent
// fix already verified above for TIMESTAMPTZ/DATE).
$gotInterval = Protocol::decodeValue(
    Protocol::encodeParam(['kind' => 'interval', 'months' => 14, 'days' => 3, 'nanos' => 4 * 3_600_000_000_000]),
    0
);
if ($gotInterval['kind'] !== Client::KIND_INTERVAL || $gotInterval['value'] !== ['months' => 14, 'days' => 3, 'nanos' => 4 * 3_600_000_000_000]) {
    fail('interval round trip -> ' . var_export($gotInterval, true));
}
$gotNegInterval = Protocol::decodeValue(
    Protocol::encodeParam(['kind' => 'interval', 'months' => 0, 'days' => 0, 'nanos' => -3_600_000_000_000]),
    0
);
if ($gotNegInterval['value']['nanos'] !== -3_600_000_000_000) {
    fail('negative interval nanos round trip -> ' . var_export($gotNegInterval, true));
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

// Hello's optional trailing Realm field (M2-2): omitted entirely when
// unset, so a Hello with no realm is byte-identical to the pre-realm wire
// shape; present as one more u16-length-prefixed string when set.
$helloNoRealm = Protocol::encodeHello([
    'version' => 1, 'flags' => 0, 'secret' => "\x00\x00\x00\x00\x00\x00\x00\x00",
    'database' => 'production', 'user' => 'app',
]);
$helloEmptyRealm = Protocol::encodeHello([
    'version' => 1, 'flags' => 0, 'secret' => "\x00\x00\x00\x00\x00\x00\x00\x00",
    'database' => 'production', 'user' => 'app', 'realm' => '',
]);
if ($helloNoRealm !== $helloEmptyRealm) {
    fail('hello with empty realm must be byte-identical to no realm key');
}
$helloWithRealm = Protocol::encodeHello([
    'version' => 1, 'flags' => 0, 'secret' => "\x00\x00\x00\x00\x00\x00\x00\x00",
    'database' => 'production', 'user' => 'app', 'realm' => 'tenant-a',
]);
if (strlen($helloWithRealm) !== strlen($helloNoRealm) + 2 + strlen('tenant-a')) {
    fail('hello with realm: unexpected length ' . strlen($helloWithRealm));
}
if (substr($helloWithRealm, 0, strlen($helloNoRealm)) !== $helloNoRealm) {
    fail('hello with realm must extend the no-realm prefix unchanged');
}

fwrite(STDOUT, "ok\n");
