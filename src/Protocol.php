<?php

declare(strict_types=1);

namespace NextSQL;

/** Wire helpers for NSQL v1. */
final class Protocol
{
    public static function u16(string $b, int $off): int
    {
        $a = unpack('v', substr($b, $off, 2));
        if ($a === false) {
            throw new Exception('protocol', 'truncated u16');
        }
        return $a[1];
    }

    public static function u32(string $b, int $off): int
    {
        $a = unpack('V', substr($b, $off, 4));
        if ($a === false) {
            throw new Exception('protocol', 'truncated u32');
        }
        return $a[1];
    }

    public static function u16le(int $n): string
    {
        return pack('v', $n);
    }

    public static function u32le(int $n): string
    {
        return pack('V', $n);
    }

    public static function u64le(string $eightBytes): string
    {
        return $eightBytes;
    }

    public static function u16str(string $s, int $max = Client::MAX_NAME): string
    {
        if (strlen($s) > $max || strlen($s) > 0xFFFF) {
            throw new Exception('protocol', 'string exceeds limit');
        }
        return self::u16le(strlen($s)) . $s;
    }

    public static function u32bytes(string $s, int $max): string
    {
        if (strlen($s) > $max) {
            throw new Exception('protocol', 'bytes exceed limit');
        }
        return self::u32le(strlen($s)) . $s;
    }

    /**
     * @return array{value: string, next: int}
     */
    public static function readU16String(string $b, int $off, int $max): array
    {
        if ($off + 2 > strlen($b)) {
            throw new Exception('protocol', 'truncated string length');
        }
        $n = self::u16($b, $off);
        if ($n > $max || $off + 2 + $n > strlen($b)) {
            throw new Exception('protocol', 'truncated string');
        }
        return ['value' => substr($b, $off + 2, $n), 'next' => $off + 2 + $n];
    }

    /**
     * @return array{value: string, next: int}
     */
    public static function readU32Bytes(string $b, int $off, int $max): array
    {
        if ($off + 4 > strlen($b)) {
            throw new Exception('protocol', 'truncated bytes length');
        }
        $n = self::u32($b, $off);
        if ($n > $max || $off + 4 + $n > strlen($b)) {
            throw new Exception('protocol', 'truncated bytes');
        }
        return ['value' => substr($b, $off + 4, $n), 'next' => $off + 4 + $n];
    }

    /**
     * @param array{version:int,flags:int,secret:string,database:string,user:string,realm?:string} $h
     */
    public static function encodeHello(array $h): string
    {
        $sec = $h['secret'];
        if (strlen($sec) !== 8) {
            $sec = str_pad(substr($sec, 0, 8), 8, "\x00");
        }
        $out = self::u16le($h['version']) . self::u16le($h['flags']) . $sec
            . self::u16str($h['database']) . self::u16str($h['user']);
        // Realm is an optional trailing field (M2-2): emitted only when
        // selected, so a Hello with no realm is byte-identical to the
        // pre-realm wire shape.
        $realm = $h['realm'] ?? '';
        if ($realm !== '') {
            $out .= self::u16str($realm);
        }
        return $out;
    }

    /**
     * @return array{version:int,authMethod:int,secret:string}
     */
    public static function decodeHelloOK(string $b): array
    {
        if (strlen($b) !== 11) {
            throw new Exception('protocol', 'bad hello-ok length');
        }
        return [
            'version' => self::u16($b, 0),
            'authMethod' => ord($b[2]),
            'secret' => substr($b, 3, 8),
        ];
    }

    /**
     * @param list<mixed> $params
     */
    public static function encodeQuery(string $sql, array $params): string
    {
        if (count($params) > Client::MAX_PARAMS) {
            throw new Exception('protocol', 'too many parameters');
        }
        $out = self::u32bytes($sql, Client::MAX_SQL) . self::u16le(count($params));
        foreach ($params as $p) {
            $out .= self::u16str('') . self::encodeParam($p);
        }
        return $out;
    }

    /**
     * @param list<mixed> $params
     */
    public static function encodeExecute(int $id, array $params): string
    {
        if (count($params) > Client::MAX_PARAMS) {
            throw new Exception('protocol', 'too many parameters');
        }
        $out = self::u32le($id) . self::u16le(count($params));
        foreach ($params as $p) {
            $out .= self::u16str('') . self::encodeParam($p);
        }
        return $out;
    }

    public static function encodeParam(mixed $v): string
    {
        if ($v === null) {
            return chr(Client::KIND_STRING) . chr(Client::FLAG_NULL) . str_repeat("\x00", 5);
        }
        if (is_bool($v)) {
            return chr(Client::KIND_BOOL) . "\x00" . str_repeat("\x00", 5) . ($v ? "\x01" : "\x00");
        }
        if (is_int($v) || is_float($v)) {
            if (is_float($v) && !is_finite($v)) {
                throw new Exception('invalid_argument', 'parameter is not finite');
            }
            $s = is_int($v) ? (string) $v : (string) $v;
            return chr(Client::KIND_DECIMAL) . "\x00" . str_repeat("\x00", 5) . self::encodeDecimal($s);
        }
        if (is_string($v)) {
            return chr(Client::KIND_STRING) . "\x00" . str_repeat("\x00", 5) . self::u32bytes($v, Client::MAX_PACKET);
        }
        if ($v instanceof \DateTimeInterface) {
            $ns = (string) ((int) $v->format('U') * 1_000_000_000 + ((int) $v->format('u')) * 1000);
            return chr(Client::KIND_TIMESTAMPTZ) . "\x00" . str_repeat("\x00", 5) . self::u64fromDec($ns);
        }
        if (is_array($v)) {
            if (array_is_list($v) && $v !== [] && array_reduce($v, static fn($ok, $x) => $ok && is_numeric($x), true)) {
                return self::encodeVector($v);
            }
            if (isset($v['lon'], $v['lat'])) {
                return chr(Client::KIND_POINT) . "\x00" . str_repeat("\x00", 5)
                    . pack('e', (float) $v['lon']) . pack('e', (float) $v['lat']);
            }
            if (isset($v['west'], $v['south'], $v['east'], $v['north'])) {
                return chr(Client::KIND_BOX) . "\x00" . str_repeat("\x00", 5)
                    . pack('e', (float) $v['west']) . pack('e', (float) $v['south'])
                    . pack('e', (float) $v['east']) . pack('e', (float) $v['north']);
            }
            if (($v['kind'] ?? '') === 'decimal') {
                return chr(Client::KIND_DECIMAL) . "\x00" . str_repeat("\x00", 5) . self::encodeDecimal((string) $v['value']);
            }
            if (($v['kind'] ?? '') === 'blob') {
                return chr(Client::KIND_BLOB) . "\x00" . str_repeat("\x00", 5) . self::u32bytes((string) $v['value'], Client::MAX_PACKET);
            }
            $intKinds = [
                'int8' => [Client::KIND_INT8, -0x80, 0x7f],
                'int16' => [Client::KIND_INT16, -0x8000, 0x7fff],
                'int32' => [Client::KIND_INT32, -0x80000000, 0x7fffffff],
                'int64' => [Client::KIND_INT64, PHP_INT_MIN, PHP_INT_MAX],
            ];
            if (isset($intKinds[$v['kind'] ?? ''])) {
                return self::encodeInt($intKinds[$v['kind']], (int) $v['value']);
            }
            $uintKinds = [
                'uint8' => Client::KIND_UINT8,
                'uint16' => Client::KIND_UINT16,
                'uint32' => Client::KIND_UINT32,
                'uint64' => Client::KIND_UINT64,
            ];
            if (isset($uintKinds[$v['kind'] ?? ''])) {
                return self::encodeUint($uintKinds[$v['kind']], $v['value']);
            }
            $json = json_encode($v, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
            return chr(Client::KIND_STRING) . "\x00" . str_repeat("\x00", 5) . self::u32bytes($json, Client::MAX_PACKET);
        }
        throw new Exception('invalid_argument', 'unsupported parameter type');
    }

    /**
     * @return array{value: mixed, next: int, kind: int}
     */
    public static function decodeValue(string $b, int $off): array
    {
        if ($off + 7 > strlen($b)) {
            throw new Exception('protocol', 'truncated value header');
        }
        $kind = ord($b[$off]);
        $flags = ord($b[$off + 1]);
        $off += 7;
        if ($flags & Client::FLAG_NULL) {
            return ['value' => null, 'next' => $off, 'kind' => $kind];
        }
        switch ($kind) {
            case Client::KIND_UUID:
                return ['value' => self::formatUUID(substr($b, $off, 16)), 'next' => $off + 16, 'kind' => $kind];
            case Client::KIND_STRING:
            case Client::KIND_TEXT:
            case Client::KIND_BLOB:
                $got = self::readU32Bytes($b, $off, Client::MAX_PACKET);
                return ['value' => $got['value'], 'next' => $got['next'], 'kind' => $kind];
            case Client::KIND_JSON:
                $got = self::readU32Bytes($b, $off, Client::MAX_PACKET);
                return ['value' => self::decodeNSJB($got['value']), 'next' => $got['next'], 'kind' => $kind];
            case Client::KIND_DECIMAL:
                $got = self::readU32Bytes($b, $off, Client::MAX_PACKET);
                return ['value' => self::decodeDecimal($got['value']), 'next' => $got['next'], 'kind' => $kind];
            case Client::KIND_TIMESTAMPTZ:
                $ns = self::i64($b, $off);
                $sec = intdiv($ns, 1_000_000_000);
                $usec = intdiv($ns % 1_000_000_000, 1000);
                $dt = \DateTimeImmutable::createFromFormat('U.u', sprintf('%d.%06d', $sec, $usec), new \DateTimeZone('UTC'));
                return ['value' => $dt, 'next' => $off + 8, 'kind' => $kind];
            case Client::KIND_BOOL:
                return ['value' => ord($b[$off]) !== 0, 'next' => $off + 1, 'kind' => $kind];
            case Client::KIND_INT8:
                $v = ord($b[$off]);
                return ['value' => $v >= 0x80 ? $v - 0x100 : $v, 'next' => $off + 1, 'kind' => $kind];
            case Client::KIND_INT16:
                $v = self::u16($b, $off);
                return ['value' => $v >= 0x8000 ? $v - 0x10000 : $v, 'next' => $off + 2, 'kind' => $kind];
            case Client::KIND_INT32:
                $v = self::u32($b, $off);
                return ['value' => $v >= 0x80000000 ? $v - (2 ** 32) : $v, 'next' => $off + 4, 'kind' => $kind];
            case Client::KIND_INT64:
                // PHP int is platform-width (64-bit on every mainstream
                // build); a legacy 32-bit build cannot represent the full
                // range (see docs/design-datatypes.md D2).
                return ['value' => self::i64($b, $off), 'next' => $off + 8, 'kind' => $kind];
            case Client::KIND_UINT8:
                return ['value' => ord($b[$off]), 'next' => $off + 1, 'kind' => $kind];
            case Client::KIND_UINT16:
                return ['value' => self::u16($b, $off), 'next' => $off + 2, 'kind' => $kind];
            case Client::KIND_UINT32:
                return ['value' => self::u32($b, $off), 'next' => $off + 4, 'kind' => $kind];
            case Client::KIND_UINT64:
                // Exposed as a native int when it fits PHP's signed 64-bit
                // range (< 2^63), else as a decimal string (mirrors DECIMAL)
                // — PHP has no unsigned 64-bit type, so a value at/above
                // 2^63 cannot be a plain int without silently going negative
                // (see docs/design-datatypes.md D3).
                return ['value' => self::decodeUint64($b, $off), 'next' => $off + 8, 'kind' => $kind];
            case Client::KIND_VECTOR:
                $dim = self::u16($b, $off);
                $flag = ord($b[$off + 2]);
                if ($flag & 1) {
                    return ['value' => ['ref' => true, 'dim' => $dim], 'next' => $off + 3, 'kind' => $kind];
                }
                if ($flag & 2) {
                    $nnz = unpack('V', substr($b, $off + 3, 4))[1];
                    $indices = [];
                    $values = [];
                    for ($i = 0; $i < $nnz; $i++) {
                        $indices[] = unpack('V', substr($b, $off + 7 + $i * 8, 4))[1];
                        $values[] = unpack('e', substr($b, $off + 11 + $i * 8, 4))[1];
                    }
                    return ['value' => ['dim' => $dim, 'indices' => $indices, 'values' => $values], 'next' => $off + 7 + $nnz * 8, 'kind' => $kind];
                }
                $out = [];
                for ($i = 0; $i < $dim; $i++) {
                    $out[] = unpack('e', substr($b, $off + 3 + $i * 4, 4))[1];
                }
                return ['value' => $out, 'next' => $off + 3 + $dim * 4, 'kind' => $kind];
            case Client::KIND_POINT:
                return [
                    'value' => [
                        'lon' => unpack('e', substr($b, $off, 8))[1],
                        'lat' => unpack('e', substr($b, $off + 8, 8))[1],
                    ],
                    'next' => $off + 16,
                    'kind' => $kind,
                ];
            case Client::KIND_BOX:
                return [
                    'value' => [
                        'west' => unpack('e', substr($b, $off, 8))[1],
                        'south' => unpack('e', substr($b, $off + 8, 8))[1],
                        'east' => unpack('e', substr($b, $off + 16, 8))[1],
                        'north' => unpack('e', substr($b, $off + 24, 8))[1],
                    ],
                    'next' => $off + 32,
                    'kind' => $kind,
                ];
            case Client::KIND_LINE:
                $n = self::u16($b, $off);
                $p = $off + 2;
                $coords = [];
                for ($i = 0; $i < $n * 2; $i++) {
                    $coords[] = unpack('e', substr($b, $p, 8))[1];
                    $p += 8;
                }
                return ['value' => ['coords' => $coords], 'next' => $p, 'kind' => $kind];
            case Client::KIND_POLYGON:
                $nr = self::u16($b, $off);
                $p = $off + 2;
                $rings = [];
                for ($r = 0; $r < $nr; $r++) {
                    $np = self::u16($b, $p);
                    $p += 2;
                    $ring = [];
                    for ($i = 0; $i < $np * 2; $i++) {
                        $ring[] = unpack('e', substr($b, $p, 8))[1];
                        $p += 8;
                    }
                    $rings[] = $ring;
                }
                return ['value' => ['rings' => $rings], 'next' => $p, 'kind' => $kind];
            default:
                throw new Exception('protocol', 'unsupported type');
        }
    }

    /**
     * @return list<array{name:string,kind:int}>
     */
    public static function decodeRowDesc(string $b): array
    {
        $n = self::u16($b, 0);
        $off = 2;
        $cols = [];
        for ($i = 0; $i < $n; $i++) {
            $name = self::readU16String($b, $off, Client::MAX_NAME);
            $off = $name['next'];
            $cols[] = ['name' => $name['value'], 'kind' => ord($b[$off])];
            $off += 6;
        }
        return $cols;
    }

    /**
     * @return list<list<mixed>>
     */
    public static function decodeDataBatch(string $b): array
    {
        $nrows = self::u32($b, 0);
        $off = 4;
        $rows = [];
        for ($i = 0; $i < $nrows; $i++) {
            $ncols = self::u16($b, $off);
            $off += 2;
            $row = [];
            for ($j = 0; $j < $ncols; $j++) {
                $got = self::decodeValue($b, $off);
                $row[] = $got['value'];
                $off = $got['next'];
            }
            $rows[] = $row;
        }
        return $rows;
    }

    public static function decodeCommandComplete(string $b): int
    {
        if (strlen($b) !== 8) {
            throw new Exception('protocol', 'bad command-complete length');
        }
        $lo = self::u32($b, 0);
        $hi = self::u32($b, 4);
        return $hi * (1 << 32) + $lo;
    }

    public static function decodeError(string $b): Exception
    {
        $code = self::readU16String($b, 0, Client::MAX_NAME);
        $msg = self::readU16String($b, $code['next'], Client::MAX_NAME);
        return new Exception($code['value'], $msg['value']);
    }

    private static function packU64le(int $n): string
    {
        return self::u32le($n & 0xFFFFFFFF) . self::u32le(($n >> 32) & 0xFFFFFFFF);
    }

    private static function u64u(string $b, int $off): int
    {
        return self::u32($b, $off) + self::u32($b, $off + 4) * (1 << 32);
    }

    public static function encodeSetReadConsistency(int $mode, int $maxStalenessMs): string
    {
        if ($mode < 0 || $mode > 2) {
            throw new Exception('invalid_argument', 'unknown read consistency mode');
        }
        $ms = $maxStalenessMs > 0 ? $maxStalenessMs : 0;
        return chr($mode) . self::packU64le($ms);
    }

    /**
     * @return array{role:string,hasLeader:bool,healthy:bool,appliedLSN:int,lastContactMs:int,applyBacklog:int}
     */
    public static function decodeNodeStatus(string $b): array
    {
        $role = self::readU16String($b, 0, Client::MAX_NAME);
        $off = $role['next'];
        if (strlen($b) - $off !== 25) {
            throw new Exception('protocol', 'bad node-status length');
        }
        $flags = ord($b[$off]);
        $off++;
        // last_contact_ms is a non-negative age, or int64 -1 (uint64 max) for a
        // follower that has never heard from a leader.
        $lcHi = self::u32($b, $off + 12);
        $lastContactMs = $lcHi === 0xFFFFFFFF ? -1 : $lcHi * (1 << 32) + self::u32($b, $off + 8);
        return [
            'role' => $role['value'],
            'hasLeader' => ($flags & 1) !== 0,
            'healthy' => ($flags & 2) !== 0,
            'appliedLSN' => self::u64u($b, $off),
            'lastContactMs' => $lastContactMs,
            'applyBacklog' => self::u64u($b, $off + 16),
        ];
    }

    public static function encodeDecimal(string $s): string
    {
        $s = trim($s);
        $neg = false;
        if (str_starts_with($s, '+')) {
            $s = substr($s, 1);
        }
        if (str_starts_with($s, '-')) {
            $neg = true;
            $s = substr($s, 1);
        }
        if (!preg_match('/^\d+(\.\d+)?$/', $s)) {
            throw new Exception('invalid_argument', 'invalid decimal');
        }
        $parts = explode('.', $s, 2);
        $scale = isset($parts[1]) ? strlen($parts[1]) : 0;
        $digits = ltrim($parts[0] . ($parts[1] ?? ''), '0');
        if ($digits === '') {
            $digits = '0';
        }
        $coef = self::decToBytes($digits);
        $body = ($neg ? "\x01" : "\x00") . "\x00" . self::u16le($scale) . $coef;
        return self::u32bytes($body, Client::MAX_PACKET);
    }

    public static function decodeDecimal(string $body): string
    {
        if (strlen($body) < 4) {
            throw new Exception('invalid_format', 'truncated decimal');
        }
        $neg = (ord($body[0]) & 1) !== 0;
        $scale = self::u16($body, 2);
        $s = self::bytesToDec(substr($body, 4));
        if ($scale > 0) {
            $s = str_pad($s, $scale + 1, '0', STR_PAD_LEFT);
            $s = substr($s, 0, -$scale) . '.' . substr($s, -$scale);
        }
        if ($neg && $s !== '0' && !preg_match('/^0\.0+$/', $s)) {
            $s = '-' . $s;
        }
        return $s;
    }

    public static function formatUUID(string $raw): string
    {
        $h = bin2hex($raw);
        return substr($h, 0, 8) . '-' . substr($h, 8, 4) . '-' . substr($h, 12, 4) . '-' . substr($h, 16, 4) . '-' . substr($h, 20);
    }

    public static function decodeNSJB(string $doc): mixed
    {
        if (strlen($doc) < 5 || substr($doc, 0, 4) !== 'NSJB' || ord($doc[4]) !== 1) {
            throw new Exception('invalid_format', 'not binary JSON');
        }
        [$value, $next] = self::readNSJB($doc, 5);
        if ($next !== strlen($doc)) {
            throw new Exception('invalid_format', 'trailing JSON bytes');
        }
        return $value;
    }

    /**
     * @return array{0:mixed,1:int}
     */
    private static function readNSJB(string $b, int $off): array
    {
        if ($off >= strlen($b)) {
            throw new Exception('invalid_format', 'truncated JSON');
        }
        return match (ord($b[$off])) {
            0x00 => [null, $off + 1],
            0x01 => [false, $off + 1],
            0x02 => [true, $off + 1],
            0x03 => [self::i64($b, $off + 1), $off + 9],
            0x04 => self::readNSJBStr($b, $off, false),
            0x05 => self::readNSJBStr($b, $off, true),
            0x06 => self::readNSJBArray($b, $off),
            0x07 => self::readNSJBObject($b, $off),
            default => throw new Exception('invalid_format', 'unknown JSON tag'),
        };
    }

    /**
     * @return array{0:mixed,1:int}
     */
    private static function readNSJBStr(string $b, int $off, bool $number): array
    {
        $n = self::u32($b, $off + 1);
        $end = $off + 5 + $n;
        $s = substr($b, $off + 5, $n);
        if ($number) {
            if (is_numeric($s)) {
                return [str_contains($s, '.') ? (float) $s : (int) $s, $end];
            }
        }
        return [$s, $end];
    }

    /**
     * @return array{0:mixed,1:int}
     */
    private static function readNSJBArray(string $b, int $off): array
    {
        $size = self::u32($b, $off + 1);
        $body = $off + 5;
        $end = $body + $size;
        $count = self::u32($b, $body);
        $cur = $body + 4;
        $arr = [];
        for ($i = 0; $i < $count; $i++) {
            [$v, $cur] = self::readNSJB($b, $cur);
            $arr[] = $v;
        }
        return [$arr, $end];
    }

    /**
     * @return array{0:mixed,1:int}
     */
    private static function readNSJBObject(string $b, int $off): array
    {
        $size = self::u32($b, $off + 1);
        $body = $off + 5;
        $end = $body + $size;
        $count = self::u16($b, $body);
        $cur = $body + 2;
        $obj = [];
        for ($i = 0; $i < $count; $i++) {
            $klen = self::u16($b, $cur);
            $cur += 2;
            $key = substr($b, $cur, $klen);
            $cur += $klen;
            [$v, $cur] = self::readNSJB($b, $cur);
            $obj[$key] = $v;
        }
        return [$obj, $end];
    }

    /**
     * @param list<float|int> $arr
     */
    private static function encodeVector(array $arr): string
    {
        $dim = count($arr);
        $body = self::u16le($dim) . "\x00";
        foreach ($arr as $f) {
            $body .= pack('g', (float) $f);
        }
        $hdr = chr(Client::KIND_VECTOR) . "\x00" . self::u16le($dim) . "\x00\x00\x01";
        return $hdr . $body;
    }

    public static function decToBytes(string $digits): string
    {
        if ($digits === '0') {
            return '';
        }
        $out = '';
        while ($digits !== '0' && $digits !== '') {
            $quot = '';
            $rem = 0;
            $len = strlen($digits);
            for ($i = 0; $i < $len; $i++) {
                $acc = $rem * 10 + (int) $digits[$i];
                $q = intdiv($acc, 256);
                $rem = $acc % 256;
                if ($quot !== '' || $q !== 0) {
                    $quot .= (string) $q;
                }
            }
            $out = chr($rem) . $out;
            $digits = $quot === '' ? '0' : $quot;
        }
        return $out;
    }

    public static function bytesToDec(string $bytes): string
    {
        $s = '0';
        $n = strlen($bytes);
        for ($i = 0; $i < $n; $i++) {
            $s = self::decMulAdd($s, 256, ord($bytes[$i]));
        }
        return $s;
    }

    private static function decMulAdd(string $s, int $mul, int $add): string
    {
        $carry = $add;
        $out = '';
        for ($i = strlen($s) - 1; $i >= 0; $i--) {
            $v = ((int) $s[$i]) * $mul + $carry;
            $out = (string) ($v % 10) . $out;
            $carry = intdiv($v, 10);
        }
        while ($carry > 0) {
            $out = (string) ($carry % 10) . $out;
            $carry = intdiv($carry, 10);
        }
        $out = ltrim($out, '0');
        return $out === '' ? '0' : $out;
    }

    private static function i64(string $b, int $off): int
    {
        // Fixed while implementing D2 (Datatype expansion track): the old
        // hi*2^32+lo formula overflows into float for any value at/above
        // magnitude 2^63 (silently corrupting e.g. exactly PHP_INT_MIN),
        // because the pre-clamp arithmetic runs before the sign fixup.
        // unpack('P', ...) instead reinterprets the 8 bytes as a native
        // 64-bit register directly (no arithmetic, so no overflow) — PHP
        // int is signed 64-bit natively, so this returns the correct
        // signed value across the full range.
        return unpack('P', substr($b, $off, 8))[1];
    }

    private static function u64fromDec(string $dec): string
    {
        $bytes = self::decToBytes($dec);
        $bytes = str_pad($bytes, 8, "\x00", STR_PAD_LEFT);
        return strrev(substr($bytes, -8)); // LE
    }

    /**
     * encodeInt builds an explicit fixed-width int parameter (D2, Datatype
     * expansion track). A bare PHP int still defaults to KIND_DECIMAL (see
     * encodeParam) and coerces server-side into any numeric column, so this
     * is only needed to pin an exact wire width. Native PHP int is
     * platform-width (64-bit on every mainstream build; a legacy 32-bit PHP
     * build cannot represent the full INT64 range at all — not solvable
     * within this driver without arbitrary-precision string arithmetic).
     *
     * @param array{0: int, 1: int, 2: int} $spec [kindTag, min, max]
     */
    private static function encodeInt(array $spec, int $value): string
    {
        [$kindTag, $min, $max] = $spec;
        if ($value < $min || $value > $max) {
            throw new Exception('invalid_argument', 'integer out of range');
        }
        $body = match ($kindTag) {
            Client::KIND_INT8 => chr($value & 0xFF),
            Client::KIND_INT16 => pack('v', $value & 0xFFFF),
            Client::KIND_INT32 => pack('V', $value & 0xFFFFFFFF),
            // 'P': unsigned 64-bit LE — pack() takes the raw bit pattern of
            // the native (signed) PHP int, so a negative value round-trips
            // correctly as two's complement.
            default => pack('P', $value),
        };
        return chr($kindTag) . "\x00" . str_repeat("\x00", 5) . $body;
    }

    /**
     * encodeUint builds an explicit fixed-width unsigned int parameter (D3,
     * Datatype expansion track). UINT8/16/32 always fit in PHP's native
     * 64-bit signed int; UINT64 additionally accepts a decimal digit string
     * for magnitudes above PHP_INT_MAX, since PHP has no unsigned 64-bit
     * type (mirrors how DECIMAL values are passed as strings).
     */
    private static function encodeUint(int $kindTag, int|string $value): string
    {
        $body = match ($kindTag) {
            Client::KIND_UINT8, Client::KIND_UINT16, Client::KIND_UINT32 => self::encodeNarrowUint($kindTag, $value),
            default => self::encodeUint64($value),
        };
        return chr($kindTag) . "\x00" . str_repeat("\x00", 5) . $body;
    }

    private static function encodeNarrowUint(int $kindTag, int|string $value): string
    {
        if (!is_int($value)) {
            throw new Exception('invalid_argument', 'uint value must be an integer');
        }
        $max = match ($kindTag) {
            Client::KIND_UINT8 => 0xFF,
            Client::KIND_UINT16 => 0xFFFF,
            default => 0xFFFFFFFF,
        };
        if ($value < 0 || $value > $max) {
            throw new Exception('invalid_argument', 'integer out of range');
        }
        return match ($kindTag) {
            Client::KIND_UINT8 => chr($value),
            Client::KIND_UINT16 => pack('v', $value),
            default => pack('V', $value),
        };
    }

    private static function encodeUint64(int|string $value): string
    {
        if (is_int($value)) {
            if ($value < 0) {
                throw new Exception('invalid_argument', 'integer out of range');
            }
            return pack('P', $value);
        }
        if (!preg_match('/^\d+$/D', $value)) {
            throw new Exception('invalid_argument', 'invalid uint64 value');
        }
        $bytes = self::decToBytes($value);
        if (strlen($bytes) > 8) {
            throw new Exception('invalid_argument', 'integer out of range');
        }
        return strrev(str_pad($bytes, 8, "\x00", STR_PAD_LEFT));
    }

    private static function decodeUint64(string $b, int $off): int|string
    {
        $raw = substr($b, $off, 8);
        if ((ord($raw[7]) & 0x80) === 0) {
            return unpack('P', $raw)[1];
        }
        return self::bytesToDec(strrev($raw));
    }
}
