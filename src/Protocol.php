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
     * appendEnumLabels/readEnumLabels carry an ENUM Type's declared label
     * list on the wire, matching internal/protocol/value.go's
     * appendEnumLabels/readEnumLabels exactly (docs/design-datatypes.md
     * D11): ENUM is the first D-track type whose Type needs variable-length
     * metadata beyond the fixed 5/6-byte Precision/Scale/VecElem shape every
     * other type fits into.
     */
    public static function appendEnumLabels(array $labels): string
    {
        $out = self::u16le(count($labels));
        foreach ($labels as $l) {
            $out .= self::u16str((string) $l, Client::MAX_ENUM_LABEL_BYTES);
        }
        return $out;
    }

    /**
     * @return array{value: array<int, string>, next: int}
     */
    public static function readEnumLabels(string $b, int $off): array
    {
        if ($off + 2 > strlen($b)) {
            throw new Exception('protocol', 'truncated enum label count');
        }
        $n = self::u16($b, $off);
        if ($n > Client::MAX_ENUM_LABELS) {
            throw new Exception('protocol', 'enum label count exceeds limit');
        }
        $off += 2;
        $labels = [];
        for ($i = 0; $i < $n; $i++) {
            $got = self::readU16String($b, $off, Client::MAX_ENUM_LABEL_BYTES);
            $labels[] = $got['value'];
            $off = $got['next'];
        }
        return ['value' => $labels, 'next' => $off];
    }

    // --- Collections (STRUCT / ARRAY / MAP), docs/design-collections.md ------

    /**
     * @return array{type: array<string,mixed>, next: int}
     */
    public static function readTypeFull(string $b, int $off, int $depth): array
    {
        if ($off + 6 > strlen($b)) {
            throw new Exception('protocol', 'truncated type');
        }
        $t = [
            'kind' => ord($b[$off]),
            'precision' => self::u16($b, $off + 1),
            'scale' => self::u16($b, $off + 3),
            'elem' => ord($b[$off + 5]),
        ];
        $next = self::readNestedDescriptor($b, $off + 6, $t, $depth);
        return ['type' => $t, 'next' => $next];
    }

    /** @param array<string,mixed> $t */
    public static function readNestedDescriptor(string $b, int $off, array &$t, int $depth): int
    {
        if ($depth > Client::MAX_NEST_DEPTH + 1) {
            throw new Exception('protocol', 'collection type nesting too deep');
        }
        $kind = $t['kind'];
        if ($kind === Client::KIND_ENUM) {
            $got = self::readEnumLabels($b, $off);
            $t['labels'] = $got['value'];
            return $got['next'];
        }
        if ($kind === Client::KIND_ARRAY) {
            $e = self::readTypeFull($b, $off, $depth + 1);
            $t['elemType'] = $e['type'];
            return $e['next'];
        }
        if ($kind === Client::KIND_MAP) {
            $k = self::readTypeFull($b, $off, $depth + 1);
            $v = self::readTypeFull($b, $k['next'], $depth + 1);
            $t['keyType'] = $k['type'];
            $t['elemType'] = $v['type'];
            return $v['next'];
        }
        if ($kind === Client::KIND_STRUCT) {
            if ($off + 2 > strlen($b)) {
                throw new Exception('protocol', 'truncated struct field count');
            }
            $n = self::u16($b, $off);
            if ($n === 0 || $n > Client::MAX_STRUCT_FIELDS) {
                throw new Exception('protocol', 'struct field count out of range');
            }
            $off += 2;
            $fields = [];
            for ($i = 0; $i < $n; $i++) {
                $name = self::readU16String($b, $off, 255);
                $off = $name['next'];
                $ft = self::readTypeFull($b, $off, $depth + 1);
                $off = $ft['next'];
                $fields[] = ['name' => $name['value'], 'type' => $ft['type']];
            }
            $t['fields'] = $fields;
            return $off;
        }
        return $off;
    }

    /**
     * @param array<string,mixed> $t
     * @return array{value: mixed, next: int}
     */
    public static function decodePayload(string $b, int $off, array $t): array
    {
        $kind = $t['kind'];
        if ($kind === Client::KIND_STRUCT || $kind === Client::KIND_ARRAY || $kind === Client::KIND_MAP) {
            return self::decodeCollectionPayload($b, $off, $t);
        }
        $header = chr($kind) . "\x00" . str_repeat("\x00", 5);
        if ($kind === Client::KIND_ENUM) {
            $header .= self::appendEnumLabels($t['labels'] ?? []);
        }
        $synthetic = $header . substr($b, $off);
        $got = self::decodeValue($synthetic, 0);
        return ['value' => $got['value'], 'next' => $off + ($got['next'] - strlen($header))];
    }

    /**
     * @param array<string,mixed> $t
     * @return array{value: mixed, next: int}
     */
    public static function decodeCollectionPayload(string $b, int $off, array $t): array
    {
        if ($off + 4 > strlen($b)) {
            throw new Exception('protocol', 'truncated collection');
        }
        $bodyLen = self::u32($b, $off);
        $bodyEnd = $off + 4 + $bodyLen;
        if ($bodyEnd > strlen($b)) {
            throw new Exception('protocol', 'truncated collection body');
        }
        $p = $off + 4;
        $n = self::u32($b, $p);
        $p += 4;
        if ($n > 2 * Client::MAX_COLLECTION_LEN + 2 || $n > $bodyLen) {
            throw new Exception('protocol', 'collection member count out of range');
        }
        $nb = intdiv($n + 7, 8);
        $nulls = substr($b, $p, $nb);
        $p += $nb;
        $kind = $t['kind'];
        $members = [];
        for ($i = 0; $i < $n; $i++) {
            if ((ord($nulls[intdiv($i, 8)]) & (1 << ($i % 8))) !== 0) {
                $members[] = null;
                continue;
            }
            if ($kind === Client::KIND_STRUCT) {
                $mt = $t['fields'][$i]['type'];
            } elseif ($kind === Client::KIND_ARRAY) {
                $mt = $t['elemType'];
            } else {
                $mt = ($i % 2 === 0) ? $t['keyType'] : $t['elemType'];
            }
            $got = self::decodePayload($b, $p, $mt);
            $p = $got['next'];
            $members[] = $got['value'];
        }
        if ($kind === Client::KIND_STRUCT) {
            $out = [];
            foreach ($t['fields'] as $i => $f) {
                $out[$f['name']] = $members[$i];
            }
            return ['value' => $out, 'next' => $bodyEnd];
        }
        if ($kind === Client::KIND_ARRAY) {
            return ['value' => $members, 'next' => $bodyEnd];
        }
        $out = [];
        for ($i = 0; $i + 1 < count($members); $i += 2) {
            $out[] = [$members[$i], $members[$i + 1]];
        }
        return ['value' => $out, 'next' => $bodyEnd];
    }

    /** @param array<string,mixed> $t */
    public static function encodeTypeFull(array $t): string
    {
        $out = chr($t['kind']) . str_repeat("\x00", 5);
        $kind = $t['kind'];
        if ($kind === Client::KIND_ENUM) {
            $out .= self::appendEnumLabels($t['labels'] ?? []);
        } elseif ($kind === Client::KIND_ARRAY) {
            $out .= self::encodeTypeFull($t['elemType']);
        } elseif ($kind === Client::KIND_MAP) {
            $out .= self::encodeTypeFull($t['keyType']) . self::encodeTypeFull($t['elemType']);
        } elseif ($kind === Client::KIND_STRUCT) {
            $out .= self::u16le(count($t['fields']));
            foreach ($t['fields'] as $f) {
                $out .= self::u16str($f['name'], 255) . self::encodeTypeFull($f['type']);
            }
        }
        return $out;
    }

    /**
     * @return array{type: array<string,mixed>, payload: ?string}
     */
    public static function inferValue(mixed $v): array
    {
        if ($v === null) {
            return ['type' => ['kind' => Client::KIND_STRING], 'payload' => null];
        }
        // ['kind' => 'struct', 'value' => [[name, val], ...]]
        if (is_array($v) && ($v['kind'] ?? '') === 'struct') {
            $fields = [];
            $payloads = [];
            foreach ($v['value'] as [$name, $fv]) {
                $iv = self::inferValue($fv);
                $fields[] = ['name' => (string) $name, 'type' => $iv['type']];
                $payloads[] = $iv['payload'];
            }
            return ['type' => ['kind' => Client::KIND_STRUCT, 'fields' => $fields], 'payload' => self::collectionPayload($payloads)];
        }
        // ['kind' => 'map', 'value' => [[k, v], ...]]
        if (is_array($v) && ($v['kind'] ?? '') === 'map') {
            $types = [];
            $payloads = [];
            foreach ($v['value'] as [$k, $val]) {
                $ik = self::inferValue($k);
                $ivv = self::inferValue($val);
                $types[] = $ik['type'];
                $types[] = $ivv['type'];
                $payloads[] = $ik['payload'];
                $payloads[] = $ivv['payload'];
            }
            $keyType = ['kind' => Client::KIND_STRING];
            $valType = ['kind' => Client::KIND_STRING];
            for ($i = 0; $i < count($payloads); $i++) {
                if ($payloads[$i] !== null) {
                    if ($i % 2 === 0) { $keyType = $types[$i]; } else { $valType = $types[$i]; break; }
                }
            }
            return ['type' => ['kind' => Client::KIND_MAP, 'keyType' => $keyType, 'elemType' => $valType], 'payload' => self::collectionPayload($payloads)];
        }
        // A plain list -> ARRAY.
        if (is_array($v) && array_is_list($v)) {
            $types = [];
            $payloads = [];
            foreach ($v as $x) {
                $iv = self::inferValue($x);
                $types[] = $iv['type'];
                $payloads[] = $iv['payload'];
            }
            $elemType = ['kind' => Client::KIND_STRING];
            foreach ($payloads as $i => $pl) {
                if ($pl !== null) { $elemType = $types[$i]; break; }
            }
            return ['type' => ['kind' => Client::KIND_ARRAY, 'elemType' => $elemType], 'payload' => self::collectionPayload($payloads)];
        }
        $enc = self::encodeParam($v);
        $kind = ord($enc[0]);
        $hdr = 7;
        if ($kind === Client::KIND_ENUM) {
            $lc = self::u16($enc, 7);
            $hdr = 9;
            for ($i = 0; $i < $lc; $i++) {
                $hdr += 2 + self::u16($enc, $hdr);
            }
        }
        return ['type' => ['kind' => $kind], 'payload' => substr($enc, $hdr)];
    }

    /** @param array<int, ?string> $payloads */
    public static function collectionPayload(array $payloads): string
    {
        $n = count($payloads);
        $nb = intdiv($n + 7, 8);
        $nulls = array_fill(0, max($nb, 0), 0);
        $chunks = '';
        foreach ($payloads as $i => $pl) {
            if ($pl === null) {
                $nulls[intdiv($i, 8)] |= 1 << ($i % 8);
            } else {
                $chunks .= $pl;
            }
        }
        $nullBytes = '';
        foreach ($nulls as $byte) {
            $nullBytes .= chr($byte);
        }
        $body = self::u32le($n) . $nullBytes . $chunks;
        return self::u32le(strlen($body)) . $body;
    }

    public static function encodeCollectionParam(mixed $v): string
    {
        $iv = self::inferValue($v);
        $typeBody = substr(self::encodeTypeFull($iv['type']), 1);
        return chr($iv['type']['kind']) . "\x00" . $typeBody . ($iv['payload'] ?? '');
    }

    // --- Spatial: EWKB decode (Spatial track, docs/design-spatial.md) ------

    private const EWKB_SRID_FLAG = 0x20000000;
    private const EWKB_TYPES = [
        1 => 'Point', 2 => 'LineString', 3 => 'Polygon',
        4 => 'MultiPoint', 5 => 'MultiLineString', 6 => 'MultiPolygon',
        7 => 'GeometryCollection',
    ];

    /**
     * @return array{value: array<string,mixed>, next: int}
     */
    public static function decodeEWKB(string $b, int $off, int $depth): array
    {
        if ($depth > 8) {
            throw new Exception('protocol', 'geometry nesting too deep');
        }
        if ($off + 5 > strlen($b)) {
            throw new Exception('protocol', 'truncated geometry');
        }
        if (ord($b[$off]) !== 1) {
            throw new Exception('protocol', 'only little-endian EWKB is supported');
        }
        $tword = unpack('V', substr($b, $off + 1, 4))[1];
        $gtype = $tword & ~self::EWKB_SRID_FLAG;
        $p = $off + 5;
        $srid = 0;
        if ($tword & self::EWKB_SRID_FLAG) {
            $srid = unpack('V', substr($b, $p, 4))[1];
            $p += 4;
        }
        $name = self::EWKB_TYPES[$gtype] ?? null;
        if ($name === null) {
            throw new Exception('protocol', 'unknown geometry type');
        }
        $f64 = function () use ($b, &$p): float {
            $v = unpack('e', substr($b, $p, 8))[1];
            $p += 8;
            return $v;
        };
        $u32 = function () use ($b, &$p): int {
            $v = unpack('V', substr($b, $p, 4))[1];
            $p += 4;
            return $v;
        };
        $pts = function (int $n) use ($f64): array {
            $out = [];
            for ($i = 0; $i < $n; $i++) {
                $out[] = [$f64(), $f64()];
            }
            return $out;
        };
        if ($gtype === 1) {
            return ['value' => ['type' => $name, 'srid' => $srid, 'coordinates' => [$f64(), $f64()]], 'next' => $p];
        }
        if ($gtype === 2) {
            return ['value' => ['type' => $name, 'srid' => $srid, 'coordinates' => $pts($u32())], 'next' => $p];
        }
        if ($gtype === 3) {
            $nr = $u32();
            $rings = [];
            for ($r = 0; $r < $nr; $r++) {
                $rings[] = $pts($u32());
            }
            return ['value' => ['type' => $name, 'srid' => $srid, 'coordinates' => $rings], 'next' => $p];
        }
        $np = $u32();
        $parts = [];
        for ($i = 0; $i < $np; $i++) {
            $sub = self::decodeEWKB($b, $p, $depth + 1);
            $p = $sub['next'];
            $parts[] = $sub['value'];
        }
        $g = ['type' => $name, 'srid' => $srid];
        if ($gtype === 7) {
            $g['geometries'] = $parts;
        } else {
            $g['coordinates'] = array_map(static fn($x) => $x['coordinates'], $parts);
        }
        return ['value' => $g, 'next' => $p];
    }

    /** @param array<string,mixed> $g */
    public static function geoToWKT(array $g): string
    {
        $pt = static fn(array $xy): string => "{$xy[0]} {$xy[1]}";
        $ring = static fn(array $r): string => '(' . implode(', ', array_map($pt, $r)) . ')';
        switch ($g['type']) {
            case 'Point':
                return 'POINT(' . $pt($g['coordinates']) . ')';
            case 'LineString':
                return 'LINESTRING(' . implode(', ', array_map($pt, $g['coordinates'])) . ')';
            case 'Polygon':
                return 'POLYGON(' . implode(', ', array_map($ring, $g['coordinates'])) . ')';
            case 'MultiPoint':
                return 'MULTIPOINT(' . implode(', ', array_map(static fn($c) => '(' . $pt($c) . ')', $g['coordinates'])) . ')';
            case 'MultiLineString':
                return 'MULTILINESTRING(' . implode(', ', array_map($ring, $g['coordinates'])) . ')';
            case 'MultiPolygon':
                return 'MULTIPOLYGON(' . implode(', ', array_map(
                    static fn($poly) => '(' . implode(', ', array_map($ring, $poly)) . ')',
                    $g['coordinates']
                )) . ')';
            case 'GeometryCollection':
                return 'GEOMETRYCOLLECTION(' . implode(', ', array_map([self::class, 'geoToWKT'], $g['geometries'])) . ')';
            default:
                throw new Exception('invalid_argument', 'unsupported geometry type');
        }
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
            $ns = (int) $v->format('U') * 1_000_000_000 + ((int) $v->format('u')) * 1000;
            return chr(Client::KIND_TIMESTAMPTZ) . "\x00" . str_repeat("\x00", 5) . self::i64le($ns);
        }
        if (is_array($v)) {
            if (array_is_list($v) && $v !== [] && array_reduce($v, static fn($ok, $x) => $ok && is_numeric($x), true)) {
                return self::encodeVector($v);
            }
            if (in_array($v['kind'] ?? '', ['struct', 'map'], true)) {
                return self::encodeCollectionParam($v);
            }
            if (($v['kind'] ?? '') === 'array') {
                return self::encodeCollectionParam($v['value']);
            }
            if (array_is_list($v)) {
                // A non-numeric (or empty) list is an ARRAY collection param;
                // the server re-coerces element types against the destination.
                return self::encodeCollectionParam($v);
            }
            if (($v['kind'] ?? '') === 'geometry' || ($v['kind'] ?? '') === 'geography') {
                $wkt = isset($v['wkt']) ? (string) $v['wkt'] : self::geoToWKT($v);
                if (isset($v['srid']) && !str_starts_with(strtoupper($wkt), 'SRID=')) {
                    $wkt = "SRID={$v['srid']};{$wkt}";
                }
                return chr(Client::KIND_STRING) . "\x00" . str_repeat("\x00", 5) . self::u32bytes($wkt, Client::MAX_PACKET);
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
            if (($v['kind'] ?? '') === 'enum') {
                return self::encodeEnum((string) $v['value'], (array) $v['labels']);
            }
            if (($v['kind'] ?? '') === 'date') {
                // A DateTimeInterface's UTC calendar day, or a raw signed
                // day-count integer (docs/design-datatypes.md D5). Floor
                // division, not intdiv()'s truncation-toward-zero: a
                // pre-1970 instant's epoch-seconds is negative, and intdiv
                // would round a negative non-multiple of 86400 toward 0
                // (one day too late) instead of toward -Infinity.
                if ($v['value'] instanceof \DateTimeInterface) {
                    $sec = (int) $v['value']->setTimezone(new \DateTimeZone('UTC'))->format('U');
                    $dayCount = intdiv($sec, 86400);
                    if ($sec % 86400 !== 0 && $sec < 0) {
                        $dayCount--;
                    }
                } else {
                    $dayCount = (int) $v['value'];
                }
                return chr(Client::KIND_DATE) . "\x00" . str_repeat("\x00", 5) . pack('V', $dayCount & 0xFFFFFFFF);
            }
            if (($v['kind'] ?? '') === 'time') {
                // Nanoseconds since midnight (PHP has no time-only type;
                // always non-negative, so the signed/unsigned distinction
                // in i64le doesn't matter here — used for consistency).
                return chr(Client::KIND_TIME) . "\x00" . str_repeat("\x00", 5) . self::i64le((int) $v['value']);
            }
            if (($v['kind'] ?? '') === 'timestamp') {
                // Naive/no-timezone TIMESTAMP: shares TimestampTZ's exact
                // wire shape, tagged with a different Kind — a bare
                // DateTimeInterface always means TIMESTAMPTZ (above), so
                // this wrapper is required to select the naive Kind
                // (docs/design-datatypes.md D7).
                if ($v['value'] instanceof \DateTimeInterface) {
                    $dt = $v['value']->setTimezone(new \DateTimeZone('UTC'));
                    $ns = (int) $dt->format('U') * 1_000_000_000 + ((int) $dt->format('u')) * 1000;
                } else {
                    $ns = (int) $v['value'];
                }
                return chr(Client::KIND_TIMESTAMP) . "\x00" . str_repeat("\x00", 5) . self::i64le($ns);
            }
            if (($v['kind'] ?? '') === 'float32') {
                return chr(Client::KIND_FLOAT32) . "\x00" . str_repeat("\x00", 5) . pack('g', (float) $v['value']);
            }
            if (($v['kind'] ?? '') === 'float64') {
                return chr(Client::KIND_FLOAT64) . "\x00" . str_repeat("\x00", 5) . pack('e', (float) $v['value']);
            }
            if (($v['kind'] ?? '') === 'interval') {
                // months(i32 LE) + days(i32 LE) + nanos(i64 LE) — D6,
                // Datatype expansion track. A plain string still works as
                // an INTERVAL param for INSERT/UPDATE column assignment
                // (server-side Coerce) but not inside an arithmetic
                // expression like `dur + $1`, which requires the actual
                // wire Kind.
                $months = (int) $v['months'];
                $days = (int) $v['days'];
                return chr(Client::KIND_INTERVAL) . "\x00" . str_repeat("\x00", 5)
                    . pack('V', $months & 0xFFFFFFFF) . pack('V', $days & 0xFFFFFFFF) . self::i64le((int) $v['nanos']);
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
        $enumLabels = null;
        $collType = null;
        if ($kind === Client::KIND_ENUM) {
            $got = self::readEnumLabels($b, $off);
            $enumLabels = $got['value'];
            $off = $got['next'];
        } elseif ($kind === Client::KIND_STRUCT || $kind === Client::KIND_ARRAY || $kind === Client::KIND_MAP) {
            $collType = ['kind' => $kind];
            $off = self::readNestedDescriptor($b, $off, $collType, 0);
        }
        if ($flags & Client::FLAG_NULL) {
            return ['value' => null, 'next' => $off, 'kind' => $kind, 'labels' => $enumLabels];
        }
        if ($kind === Client::KIND_STRUCT || $kind === Client::KIND_ARRAY || $kind === Client::KIND_MAP) {
            $got = self::decodeCollectionPayload($b, $off, $collType);
            return ['value' => $got['value'], 'next' => $got['next'], 'kind' => $kind];
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
                [$sec, $usec] = self::splitNanos(self::i64($b, $off));
                $dt = \DateTimeImmutable::createFromFormat('U.u', sprintf('%d.%06d', $sec, $usec), new \DateTimeZone('UTC'));
                return ['value' => $dt, 'next' => $off + 8, 'kind' => $kind];
            case Client::KIND_TIMESTAMP:
                // Naive/no-timezone: same wire shape as TIMESTAMPTZ
                // (docs/design-datatypes.md D7).
                [$sec, $usec] = self::splitNanos(self::i64($b, $off));
                $dt = \DateTimeImmutable::createFromFormat('U.u', sprintf('%d.%06d', $sec, $usec), new \DateTimeZone('UTC'));
                return ['value' => $dt, 'next' => $off + 8, 'kind' => $kind];
            case Client::KIND_DATE:
                $day = self::u32($b, $off);
                $day = $day >= 0x80000000 ? $day - (2 ** 32) : $day;
                $dt = (new \DateTimeImmutable('@0'))->setTimezone(new \DateTimeZone('UTC'))->modify("$day days");
                return ['value' => $dt, 'next' => $off + 4, 'kind' => $kind];
            case Client::KIND_TIME:
                // Nanoseconds since midnight, always non-negative.
                $ns = self::i64($b, $off);
                return ['value' => $ns, 'next' => $off + 8, 'kind' => $kind];
            case Client::KIND_CHAR:
            case Client::KIND_VARCHAR:
                $got = self::readU32Bytes($b, $off, Client::MAX_PACKET);
                return ['value' => $got['value'], 'next' => $got['next'], 'kind' => $kind];
            case Client::KIND_FLOAT32:
                return ['value' => unpack('g', substr($b, $off, 4))[1], 'next' => $off + 4, 'kind' => $kind];
            case Client::KIND_FLOAT64:
                return ['value' => unpack('e', substr($b, $off, 8))[1], 'next' => $off + 8, 'kind' => $kind];
            case Client::KIND_INTERVAL:
                $months = self::u32($b, $off);
                $months = $months >= 0x80000000 ? $months - (2 ** 32) : $months;
                $days = self::u32($b, $off + 4);
                $days = $days >= 0x80000000 ? $days - (2 ** 32) : $days;
                $nanos = self::i64($b, $off + 8);
                return [
                    'value' => ['months' => $months, 'days' => $days, 'nanos' => $nanos],
                    'next' => $off + 16,
                    'kind' => $kind,
                ];
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
            case Client::KIND_ENUM:
                if ($off + 2 > strlen($b)) {
                    throw new Exception('protocol', 'truncated enum');
                }
                $ord = self::u16($b, $off);
                if ($ord >= count($enumLabels)) {
                    throw new Exception('protocol', 'ENUM ordinal out of range');
                }
                return ['value' => $enumLabels[$ord], 'next' => $off + 2, 'kind' => $kind, 'labels' => $enumLabels];
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
            case Client::KIND_GEOMETRY:
            case Client::KIND_GEOGRAPHY:
                $len = self::u32($b, $off);
                $got = self::decodeEWKB($b, $off + 4, 0);
                return ['value' => $got['value'], 'next' => $off + 4 + $len, 'kind' => $kind];
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
     * @return list<array{name:string,kind:int,labels?:array<int,string>}>
     */
    public static function decodeRowDesc(string $b): array
    {
        $n = self::u16($b, 0);
        $off = 2;
        $cols = [];
        for ($i = 0; $i < $n; $i++) {
            $name = self::readU16String($b, $off, Client::MAX_NAME);
            $off = $name['next'];
            $kind = ord($b[$off]);
            $col = ['name' => $name['value'], 'kind' => $kind];
            $off += 6;
            if ($kind === Client::KIND_ENUM) {
                $got = self::readEnumLabels($b, $off);
                $col['labels'] = $got['value'];
                $off = $got['next'];
            } elseif ($kind === Client::KIND_STRUCT || $kind === Client::KIND_ARRAY || $kind === Client::KIND_MAP) {
                $ct = ['kind' => $kind];
                $off = self::readNestedDescriptor($b, $off, $ct, 0);
                $col['collType'] = $ct;
            }
            $cols[] = $col;
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
     * i64le packs a native PHP int (already signed 64-bit) as 8
     * little-endian bytes — the mirror of i64()'s unpack('P', ...), correct
     * for the full signed range including negative values, since 'P' packs
     * the int's own two's-complement bit pattern rather than reinterpreting
     * it as unsigned magnitude.
     *
     * Found and fixed while implementing D5/D7 (Datatype expansion track):
     * every i64-range caller (TIMESTAMPTZ, and the new naive TIMESTAMP/TIME)
     * previously round-tripped through u64fromDec()/decToBytes(), which
     * treats its input as an unsigned decimal digit string — decToBytes
     * silently mistreats a leading '-' as the digit 0 (PHP's (int) cast on
     * a non-digit character), so any negative nanosecond value (any
     * pre-1970 TIMESTAMPTZ/TIMESTAMP) encoded to the wrong bytes with no
     * error. u64fromDec()/decToBytes() remain correct and necessary for
     * UINT64, whose magnitude can exceed PHP_INT_MAX and genuinely needs
     * unsigned big-number arithmetic; i64-range values never need that.
     */
    private static function i64le(int $n): string
    {
        return pack('P', $n);
    }

    /**
     * splitNanos splits epoch nanoseconds into (seconds, microseconds) with
     * microseconds always in [0, 999999] — floor division, not intdiv()'s
     * truncation-toward-zero and PHP's dividend-signed %, which for a
     * negative $ns (any pre-1970 instant) produced a negative $usec and
     * made DateTimeImmutable::createFromFormat('U.u', ...) silently return
     * false. Found and fixed alongside the i64le encode-side bug above,
     * same root cause (D5/D7, Datatype expansion track): a pre-1970
     * TIMESTAMPTZ never worked correctly in this driver.
     *
     * @return array{0: int, 1: int}
     */
    private static function splitNanos(int $ns): array
    {
        $sec = intdiv($ns, 1_000_000_000);
        $rem = $ns % 1_000_000_000;
        if ($rem < 0) {
            $rem += 1_000_000_000;
            $sec--;
        }
        return [$sec, intdiv($rem, 1000)];
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
     * encodeEnum builds an explicit ENUM parameter (D11, Datatype expansion
     * track). Ordinary INSERT/UPDATE params can just pass a plain PHP
     * string — the server coerces STRING -> ENUM against the destination
     * column, same as a SQL string literal. This wrapper exists for
     * explicit round-tripping and mirrors encodeInt/encodeUint's precedent.
     *
     * @param array<int, string> $labels
     */
    private static function encodeEnum(string $label, array $labels): string
    {
        $ord = array_search($label, $labels, true);
        if ($ord === false) {
            throw new Exception('invalid_argument', 'value is not a member of the ENUM label set');
        }
        return chr(Client::KIND_ENUM) . "\x00" . str_repeat("\x00", 5)
            . self::appendEnumLabels($labels) . self::u16le((int) $ord);
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
