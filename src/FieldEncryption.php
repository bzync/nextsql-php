<?php

declare(strict_types=1);

namespace NextSQL;

/** Portable randomized NSCE1 AES-256-GCM field encryption. */
final class FieldEncryption
{
    public const PREFIX = 'NSCE1.';
    public const MAX_PLAINTEXT = 1 << 20;
    private const MAX_KEY_ID = 64;
    private const NONCE_SIZE = 12;
    private const TAG_SIZE = 16;

    /** @return array{id:string,material:string} */
    public static function generateKey(string $id): array
    {
        if (!self::validKeyID($id)) {
            throw new Exception('invalid_argument', 'invalid field key id');
        }
        try {
            return ['id' => $id, 'material' => random_bytes(32)];
        } catch (\Throwable) {
            throw new Exception('crypto', 'field key generation failed');
        }
    }

    /** @param array{id:string,material:string} $key */
    public static function validateKey(array $key): void
    {
        if (!isset($key['id'], $key['material']) || !is_string($key['material']) ||
            !self::validKeyID($key['id']) || strlen($key['material']) !== 32 || $key['material'] === str_repeat("\x00", 32)) {
            throw new Exception('invalid_argument', 'invalid field key');
        }
    }

    /** @param array{kind:int,precision:int,scale:int,vecElem:int} $type */
    public static function encrypt(
        FieldKeyProvider $provider,
        string $database,
        string $table,
        string $column,
        array $type,
        mixed $value
    ): ?string {
        $type = self::normalizeType($type);
        if ($value === null) {
            return null;
        }
        $plain = self::encodeScalar($type, $value);
        if (strlen($plain) > self::MAX_PLAINTEXT) {
            throw new Exception('exhausted', 'plaintext exceeds field limit');
        }
        try {
            $key = $provider->currentFieldKey($database, $table, $column);
            self::validateKey($key);
        } catch (\Throwable) {
            throw new Exception('crypto', 'field key unavailable');
        }
        try {
            $nonce = random_bytes(self::NONCE_SIZE);
            $header = self::header($key['id'], $type, $nonce);
            $public = substr($header, 0, -self::NONCE_SIZE);
            $tag = '';
            $sealed = openssl_encrypt(
                $plain,
                'aes-256-gcm',
                $key['material'],
                OPENSSL_RAW_DATA,
                $nonce,
                $tag,
                self::aad($database, $table, $column, $public),
                self::TAG_SIZE
            );
            if ($sealed === false || strlen($tag) !== self::TAG_SIZE) {
                throw new \RuntimeException('AES-GCM failed');
            }
            return self::PREFIX . rtrim(strtr(base64_encode($header . $sealed . $tag), '+/', '-_'), '=');
        } catch (Exception $e) {
            throw $e;
        } catch (\Throwable) {
            throw new Exception('crypto', 'field encryption failed');
        }
    }

    /** @param array{kind:int,precision:int,scale:int,vecElem:int} $expected */
    public static function decrypt(
        FieldKeyProvider $provider,
        string $database,
        string $table,
        string $column,
        array $expected,
        ?string $ciphertext
    ): mixed {
        $expected = self::normalizeType($expected);
        if ($ciphertext === null) {
            return null;
        }
        $parsed = self::inspect($ciphertext);
        if ($parsed['type'] !== $expected) {
            throw new Exception('invalid_format', 'encrypted logical type mismatch');
        }
        try {
            $key = $provider->fieldKey($database, $table, $column, $parsed['keyID']);
            self::validateKey($key);
            if ($key['id'] !== $parsed['keyID']) {
                throw new \RuntimeException('wrong key id');
            }
        } catch (\Throwable) {
            throw new Exception('crypto', 'field key unavailable or revoked');
        }
        $body = $parsed['body'];
        $headerLength = $parsed['headerLength'];
        $nonce = substr($body, $headerLength - self::NONCE_SIZE, self::NONCE_SIZE);
        $payload = substr($body, $headerLength);
        $tag = substr($payload, -self::TAG_SIZE);
        $sealed = substr($payload, 0, -self::TAG_SIZE);
        $plain = openssl_decrypt(
            $sealed,
            'aes-256-gcm',
            $key['material'],
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            self::aad($database, $table, $column, substr($body, 0, $headerLength - self::NONCE_SIZE))
        );
        if ($plain === false) {
            throw new Exception('crypto', 'ciphertext authentication failed');
        }
        if (strlen($plain) > self::MAX_PLAINTEXT) {
            throw new Exception('invalid_format', 'plaintext exceeds field limit');
        }
        return self::decodeScalar($expected, $plain);
    }

    /** @return array{keyID:string,type:array{kind:int,precision:int,scale:int,vecElem:int},body:string,headerLength:int} */
    public static function inspect(string $ciphertext): array
    {
        if (!str_starts_with($ciphertext, self::PREFIX)) {
            throw new Exception('invalid_format', 'invalid client ciphertext prefix');
        }
        $encoded = substr($ciphertext, strlen(self::PREFIX));
        $maxEncoded = (int) ceil((self::MAX_PLAINTEXT + 101) * 4 / 3);
        if ($encoded === '' || strlen($encoded) > $maxEncoded || strlen($encoded) % 4 === 1 ||
            !preg_match('/^[A-Za-z0-9_-]+$/D', $encoded)) {
            throw new Exception('invalid_format', 'client ciphertext length out of range');
        }
        $padded = strtr($encoded, '-_', '+/') . str_repeat('=', (4 - strlen($encoded) % 4) % 4);
        $body = base64_decode($padded, true);
        if ($body === false || rtrim(strtr(base64_encode($body), '+/', '-_'), '=') !== $encoded ||
            strlen($body) < 38 || ord($body[0]) !== 1 || ord($body[1]) !== 1) {
            throw new Exception('invalid_format', 'unsupported or truncated client ciphertext');
        }
        $n = ord($body[2]);
        if ($n < 1 || $n > self::MAX_KEY_ID || strlen($body) < 3 + $n + 6 + self::NONCE_SIZE + self::TAG_SIZE) {
            throw new Exception('invalid_format', 'invalid field key id length');
        }
        $keyID = substr($body, 3, $n);
        if (!self::validKeyID($keyID)) {
            throw new Exception('invalid_format', 'invalid field key id');
        }
        $off = 3 + $n;
        $type = self::normalizeType([
            'kind' => ord($body[$off]),
            'precision' => Protocol::u16($body, $off + 1),
            'scale' => Protocol::u16($body, $off + 3),
            'vecElem' => ord($body[$off + 5]),
        ], 'invalid_format');
        return ['keyID' => $keyID, 'type' => $type, 'body' => $body, 'headerLength' => $off + 6 + self::NONCE_SIZE];
    }

    /** @param array{kind:int,precision:int,scale:int,vecElem:int} $type */
    private static function encodeScalar(array $type, mixed $value): string
    {
        return match ($type['kind']) {
            Client::KIND_UUID => self::encodeUUID($value),
            Client::KIND_STRING, Client::KIND_TEXT => is_string($value)
                ? Protocol::u32bytes($value, self::MAX_PLAINTEXT)
                : throw new Exception('invalid_argument', 'encrypted string value must be a string'),
            Client::KIND_BLOB => is_string($value)
                ? Protocol::u32bytes($value, self::MAX_PLAINTEXT)
                : throw new Exception('invalid_argument', 'encrypted BLOB value must be a (byte) string'),
            Client::KIND_DECIMAL => self::encodeDecimal($type, $value),
            Client::KIND_TIMESTAMPTZ => self::encodeTimestamp($value),
            Client::KIND_JSON => Protocol::u32bytes(self::encodeNSJB($value), self::MAX_PLAINTEXT),
            Client::KIND_BOOL => is_bool($value)
                ? ($value ? "\x01" : "\x00")
                : throw new Exception('invalid_argument', 'encrypted BOOL value must be boolean'),
            Client::KIND_INT8, Client::KIND_INT16, Client::KIND_INT32, Client::KIND_INT64 =>
                self::encodeInt($type['kind'], $value),
            Client::KIND_UINT8, Client::KIND_UINT16, Client::KIND_UINT32, Client::KIND_UINT64 =>
                self::encodeUint($type['kind'], $value),
            default => throw new Exception('invalid_argument', 'unsupported client-encrypted type'),
        };
    }

    /**
     * encodeInt/decodeInt (D2, Datatype expansion track) use the same
     * fixed-width raw-byte plaintext shape as the server's row encoding
     * (internal/sql/types/row.go encodeScalar) — not the length-prefixed
     * shape STRING/BLOB/DECIMAL use — so any official driver can decrypt a
     * field another driver encrypted.
     */
    private static function encodeInt(int $kind, mixed $value): string
    {
        if (!is_int($value)) {
            throw new Exception('invalid_argument', 'encrypted int value must be an integer');
        }
        [$min, $max] = match ($kind) {
            Client::KIND_INT8 => [-0x80, 0x7f],
            Client::KIND_INT16 => [-0x8000, 0x7fff],
            Client::KIND_INT32 => [-0x80000000, 0x7fffffff],
            default => [PHP_INT_MIN, PHP_INT_MAX],
        };
        if ($value < $min || $value > $max) {
            throw new Exception('invalid_argument', 'encrypted int value out of range');
        }
        return match ($kind) {
            Client::KIND_INT8 => chr($value & 0xFF),
            Client::KIND_INT16 => pack('v', $value & 0xFFFF),
            Client::KIND_INT32 => pack('V', $value & 0xFFFFFFFF),
            default => pack('P', $value),
        };
    }

    private static function decodeInt(int $kind, string $raw): int
    {
        $width = match ($kind) {
            Client::KIND_INT8 => 1,
            Client::KIND_INT16 => 2,
            Client::KIND_INT32 => 4,
            default => 8,
        };
        if (strlen($raw) !== $width) {
            throw new Exception('invalid_format', 'invalid encrypted value');
        }
        return match ($kind) {
            Client::KIND_INT8 => ord($raw[0]) >= 0x80 ? ord($raw[0]) - 0x100 : ord($raw[0]),
            Client::KIND_INT16 => (fn ($v) => $v >= 0x8000 ? $v - 0x10000 : $v)(Protocol::u16($raw, 0)),
            Client::KIND_INT32 => (fn ($v) => $v >= 0x80000000 ? $v - (2 ** 32) : $v)(Protocol::u32($raw, 0)),
            default => unpack('P', $raw)[1],
        };
    }

    /**
     * encodeUint/decodeUint (D3, Datatype expansion track) mirror
     * encodeInt/decodeInt. UINT64 additionally accepts/returns a decimal
     * digit string for magnitudes above PHP_INT_MAX, since PHP has no
     * unsigned 64-bit type (mirrors DECIMAL's string representation).
     */
    private static function encodeUint(int $kind, mixed $value): string
    {
        if ($kind !== Client::KIND_UINT64) {
            if (!is_int($value)) {
                throw new Exception('invalid_argument', 'encrypted uint value must be an integer');
            }
            $max = match ($kind) {
                Client::KIND_UINT8 => 0xFF,
                Client::KIND_UINT16 => 0xFFFF,
                default => 0xFFFFFFFF,
            };
            if ($value < 0 || $value > $max) {
                throw new Exception('invalid_argument', 'encrypted uint value out of range');
            }
            return match ($kind) {
                Client::KIND_UINT8 => chr($value),
                Client::KIND_UINT16 => pack('v', $value),
                default => pack('V', $value),
            };
        }
        if (is_int($value)) {
            if ($value < 0) {
                throw new Exception('invalid_argument', 'encrypted uint value out of range');
            }
            return pack('P', $value);
        }
        if (!is_string($value) || !preg_match('/^\d+$/D', $value)) {
            throw new Exception('invalid_argument', 'encrypted uint value must be a non-negative integer or decimal string');
        }
        $bytes = Protocol::decToBytes($value);
        if (strlen($bytes) > 8) {
            throw new Exception('invalid_argument', 'encrypted uint value out of range');
        }
        return strrev(str_pad($bytes, 8, "\x00", STR_PAD_LEFT));
    }

    private static function decodeUint(int $kind, string $raw): int|string
    {
        $width = match ($kind) {
            Client::KIND_UINT8 => 1,
            Client::KIND_UINT16 => 2,
            Client::KIND_UINT32 => 4,
            default => 8,
        };
        if (strlen($raw) !== $width) {
            throw new Exception('invalid_format', 'invalid encrypted value');
        }
        return match ($kind) {
            Client::KIND_UINT8 => ord($raw[0]),
            Client::KIND_UINT16 => Protocol::u16($raw, 0),
            Client::KIND_UINT32 => Protocol::u32($raw, 0),
            default => (ord($raw[7]) & 0x80) === 0
                ? unpack('P', $raw)[1]
                : Protocol::bytesToDec(strrev($raw)),
        };
    }

    /** @param array{kind:int,precision:int,scale:int,vecElem:int} $type */
    private static function decodeScalar(array $type, string $raw): mixed
    {
        return match ($type['kind']) {
            Client::KIND_UUID => strlen($raw) === 16
                ? Protocol::formatUUID($raw)
                : throw new Exception('invalid_format', 'invalid encrypted value'),
            Client::KIND_STRING, Client::KIND_TEXT, Client::KIND_BLOB => self::decodeLengthString($raw),
            Client::KIND_DECIMAL => Protocol::decodeDecimal(self::decodeLengthString($raw)),
            Client::KIND_TIMESTAMPTZ => self::decodeTimestamp($raw),
            Client::KIND_JSON => Protocol::decodeNSJB(self::decodeLengthString($raw)),
            Client::KIND_BOOL => strlen($raw) === 1 && ord($raw[0]) <= 1
                ? ord($raw[0]) === 1
                : throw new Exception('invalid_format', 'invalid encrypted value'),
            Client::KIND_INT8, Client::KIND_INT16, Client::KIND_INT32, Client::KIND_INT64 =>
                self::decodeInt($type['kind'], $raw),
            Client::KIND_UINT8, Client::KIND_UINT16, Client::KIND_UINT32, Client::KIND_UINT64 =>
                self::decodeUint($type['kind'], $raw),
            default => throw new Exception('invalid_format', 'unsupported encrypted logical type'),
        };
    }

    private static function encodeUUID(mixed $value): string
    {
        if (!is_string($value) || !preg_match('/^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$/D', $value)) {
            throw new Exception('invalid_argument', 'invalid UUID');
        }
        $raw = hex2bin(str_replace('-', '', $value));
        if ($raw === false) {
            throw new Exception('invalid_argument', 'invalid UUID');
        }
        return $raw;
    }

    /** @param array{kind:int,precision:int,scale:int,vecElem:int} $type */
    private static function encodeDecimal(array $type, mixed $value): string
    {
        if (!is_string($value) && !is_int($value)) {
            throw new Exception('invalid_argument', 'encrypted DECIMAL must be a string or integer');
        }
        $text = trim((string) $value);
        $unsigned = ltrim($text, '+-');
        if (!preg_match('/^\d+(\.\d+)?$/D', $unsigned)) {
            throw new Exception('invalid_argument', 'invalid decimal');
        }
        $parts = explode('.', $unsigned, 2);
        $fraction = $parts[1] ?? '';
        if (strlen($fraction) > $type['scale']) {
            if (trim(substr($fraction, $type['scale']), '0') !== '') {
                throw new Exception('invalid_argument', 'decimal would lose scale');
            }
            $fraction = substr($fraction, 0, $type['scale']);
        }
        $fraction = str_pad($fraction, $type['scale'], '0');
        $digits = ltrim($parts[0] . $fraction, '0');
        if (strlen($digits === '' ? '0' : $digits) > $type['precision']) {
            throw new Exception('invalid_argument', 'decimal exceeds encrypted column precision');
        }
        $sign = str_starts_with($text, '-') ? '-' : '';
        $normalized = $sign . $parts[0] . ($type['scale'] > 0 ? '.' . $fraction : '');
        $raw = Protocol::encodeDecimal($normalized);
        if (Protocol::u16($raw, 6) !== $type['scale']) {
            throw new Exception('invalid_argument', 'decimal scale does not match encrypted column type');
        }
        return $raw;
    }

    private static function encodeTimestamp(mixed $value): string
    {
        if ($value instanceof \DateTimeInterface) {
            $ns = (int) $value->format('U') * 1_000_000_000 + (int) $value->format('u') * 1000;
        } elseif (is_int($value)) {
            $ns = $value;
        } else {
            throw new Exception('invalid_argument', 'TIMESTAMPTZ must be DateTimeInterface or unix nanoseconds');
        }
        return Protocol::u32le($ns & 0xFFFFFFFF) . Protocol::u32le(($ns >> 32) & 0xFFFFFFFF);
    }

    private static function decodeTimestamp(string $raw): \DateTimeImmutable|int
    {
        if (strlen($raw) !== 8) {
            throw new Exception('invalid_format', 'invalid encrypted value');
        }
        $lo = Protocol::u32($raw, 0);
        $hi = Protocol::u32($raw, 4);
        $ns = ($hi & 0x80000000) !== 0
            ? -(((~$hi & 0xFFFFFFFF) * (1 << 32) + (~$lo & 0xFFFFFFFF)) + 1)
            : $hi * (1 << 32) + $lo;
        if ($ns % 1000 !== 0) {
            return $ns;
        }
        $sec = intdiv($ns, 1_000_000_000);
        $usec = intdiv($ns - $sec * 1_000_000_000, 1000);
        if ($usec < 0) {
            $sec--;
            $usec += 1_000_000;
        }
        $dt = \DateTimeImmutable::createFromFormat('U.u', sprintf('%d.%06d', $sec, $usec), new \DateTimeZone('UTC'));
        if ($dt === false) {
            throw new Exception('invalid_format', 'invalid encrypted timestamp');
        }
        return $dt;
    }

    private static function decodeLengthString(string $raw): string
    {
        if (strlen($raw) < 4) {
            throw new Exception('invalid_format', 'invalid encrypted value');
        }
        $n = Protocol::u32($raw, 0);
        if ($n > self::MAX_PLAINTEXT || $n + 4 !== strlen($raw)) {
            throw new Exception('invalid_format', 'invalid encrypted value');
        }
        return substr($raw, 4);
    }

    private static function encodeNSJB(mixed $value): string
    {
        $out = "NSJB\x01" . self::encodeJSONValue($value, 0);
        if (strlen($out) > self::MAX_PLAINTEXT) {
            throw new Exception('exhausted', 'JSON exceeds field limit');
        }
        return $out;
    }

    private static function encodeJSONValue(mixed $value, int $depth): string
    {
        if ($depth > 32) {
            throw new Exception('exhausted', 'JSON exceeds depth limit');
        }
        if ($value === null) return "\x00";
        if ($value === false) return "\x01";
        if ($value === true) return "\x02";
        if (is_int($value)) {
            return "\x03" . Protocol::u32le($value & 0xFFFFFFFF) . Protocol::u32le(($value >> 32) & 0xFFFFFFFF);
        }
        if (is_float($value)) {
            if (!is_finite($value)) throw new Exception('invalid_argument', 'JSON number is not finite');
            $number = json_encode($value, JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR);
            return "\x05" . Protocol::u32le(strlen($number)) . $number;
        }
        if (is_string($value)) {
            if (preg_match('//u', $value) !== 1) throw new Exception('invalid_argument', 'JSON string is not UTF-8');
            return "\x04" . Protocol::u32le(strlen($value)) . $value;
        }
        if (is_array($value) && array_is_list($value)) {
            $parts = Protocol::u32le(count($value));
            foreach ($value as $entry) {
                $parts .= self::encodeJSONValue($entry, $depth + 1);
                if (strlen($parts) > self::MAX_PLAINTEXT) throw new Exception('exhausted', 'JSON exceeds field limit');
            }
            return "\x06" . Protocol::u32le(strlen($parts)) . $parts;
        }
        if (is_array($value) || $value instanceof \stdClass) {
            $entries = is_array($value) ? $value : get_object_vars($value);
            if (count($entries) > 0xFFFF) throw new Exception('exhausted', 'JSON object exceeds limit');
            ksort($entries, SORT_STRING);
            $parts = Protocol::u16le(count($entries));
            foreach ($entries as $key => $entry) {
                $key = (string) $key;
                if (strlen($key) > 0xFFFF) throw new Exception('exhausted', 'JSON key exceeds limit');
                $parts .= Protocol::u16le(strlen($key)) . $key . self::encodeJSONValue($entry, $depth + 1);
                if (strlen($parts) > self::MAX_PLAINTEXT) throw new Exception('exhausted', 'JSON exceeds field limit');
            }
            return "\x07" . Protocol::u32le(strlen($parts)) . $parts;
        }
        throw new Exception('invalid_argument', 'unsupported JSON value');
    }

    /** @param array{kind:int,precision:int,scale:int,vecElem:int} $type */
    private static function header(string $keyID, array $type, string $nonce): string
    {
        return "\x01\x01" . chr(strlen($keyID)) . $keyID . chr($type['kind'])
            . Protocol::u16le($type['precision']) . Protocol::u16le($type['scale'])
            . chr($type['vecElem']) . $nonce;
    }

    private static function aad(string $database, string $table, string $column, string $publicHeader): string
    {
        $out = self::PREFIX;
        foreach ([$database, $table, $column] as $name) {
            if ($name === '' || strlen($name) > 0xFFFF) {
                throw new Exception('invalid_argument', 'database, table, and column are required and bounded');
            }
            $out .= Protocol::u16le(strlen($name)) . $name;
        }
        return $out . $publicHeader;
    }

    /** @param array<string,mixed> $type @return array{kind:int,precision:int,scale:int,vecElem:int} */
    private static function normalizeType(array $type, string $code = 'invalid_argument'): array
    {
        $t = [
            'kind' => (int) ($type['kind'] ?? 0),
            'precision' => (int) ($type['precision'] ?? 0),
            'scale' => (int) ($type['scale'] ?? 0),
            'vecElem' => (int) ($type['vecElem'] ?? 0),
        ];
        $scalar = in_array($t['kind'], [Client::KIND_UUID, Client::KIND_STRING, Client::KIND_TEXT, Client::KIND_BLOB,
            Client::KIND_TIMESTAMPTZ, Client::KIND_JSON, Client::KIND_BOOL,
            Client::KIND_INT8, Client::KIND_INT16, Client::KIND_INT32, Client::KIND_INT64,
            Client::KIND_UINT8, Client::KIND_UINT16, Client::KIND_UINT32, Client::KIND_UINT64], true);
        $decimal = $t['kind'] === Client::KIND_DECIMAL && $t['precision'] >= 1 && $t['precision'] <= 38
            && $t['scale'] >= 0 && $t['scale'] <= $t['precision'];
        if ((!$scalar && !$decimal) || ($scalar && ($t['precision'] !== 0 || $t['scale'] !== 0)) || $t['vecElem'] !== 0) {
            throw new Exception($code, 'unsupported client-encrypted type');
        }
        return $t;
    }

    private static function validKeyID(string $id): bool
    {
        return strlen($id) >= 1 && strlen($id) <= self::MAX_KEY_ID && preg_match('/^[A-Za-z0-9._-]+$/D', $id) === 1;
    }
}
