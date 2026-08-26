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
     * @param array{version:int,flags:int,secret:string,database:string,user:string} $h
     */
    public static function encodeHello(array $h): string
    {
        $sec = $h['secret'];
        if (strlen($sec) !== 8) {
            $sec = str_pad(substr($sec, 0, 8), 8, "\x00");
        }
        return self::u16le($h['version']) . self::u16le($h['flags']) . $sec
            . self::u16str($h['database']) . self::u16str($h['user']);
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
            case Client::KIND_VECTOR:
                $dim = self::u16($b, $off);
                $flag = ord($b[$off + 2]);
                if ($flag & 1) {
                    return ['value' => ['ref' => true, 'dim' => $dim], 'next' => $off + 3, 'kind' => $kind];
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

    private static function decToBytes(string $digits): string
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

    private static function bytesToDec(string $bytes): string
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
        $lo = self::u32($b, $off);
        $hi = self::u32($b, $off + 4);
        $u = $hi * (1 << 32) + $lo;
        if ($hi >= 0x80000000) {
            return $u - 2 ** 64;
        }
        return $u;
    }

    private static function u64fromDec(string $dec): string
    {
        $bytes = self::decToBytes($dec);
        $bytes = str_pad($bytes, 8, "\x00", STR_PAD_LEFT);
        return strrev(substr($bytes, -8)); // LE
    }
}
