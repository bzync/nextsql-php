<?php

declare(strict_types=1);

namespace NextSQL;

/**
 * Durable, atomic, file-backed FieldKeyProvider. Unlike MemoryFieldKeyring,
 * rotation and revocation persist across process restarts using the NSFK1
 * format shared with the Go, Node.js, Bun, and Deno drivers (see
 * docs/client-encryption.md):
 *
 *   magic "NSFK" (4) | version u16=1 | count u16
 *   per record: idLen u8 | id bytes | created u64 (unix seconds) |
 *     flags u8 (bit0=current, bit1=revoked) | material [32]byte
 *     (all-zero when revoked)
 *
 * A revoked key's material is overwritten with zeros on disk and its id can
 * never be reused. Production applications with an existing secret manager
 * or KMS should still prefer implementing FieldKeyProvider directly against
 * that system.
 */
final class FileFieldKeyring implements FieldKeyProvider
{
    private const MAGIC = 'NSFK';
    private const VERSION = 1;
    private const MAX_KEYS = 64;
    private const MAX_KEY_ID = 64;
    private const FLAG_CURRENT = 1;
    private const FLAG_REVOKED = 2;

    private string $path;
    /** @var array<int, array{id:string,created:int,current:bool,revoked:bool,material:string}> */
    private array $records;

    /** @param array{id:string,created:int,current:bool,revoked:bool,material:string}[] $records */
    private function __construct(string $path, array $records)
    {
        $this->path = $path;
        $this->records = $records;
    }

    /** @param array{id:string,material:string} $current */
    public static function create(string $path, array $current): self
    {
        if (file_exists($path)) {
            throw new Exception('already_exists', 'keyring file exists');
        }
        FieldEncryption::validateKey($current);
        $record = [
            'id' => $current['id'],
            'created' => time(),
            'current' => true,
            'revoked' => false,
            'material' => $current['material'],
        ];
        $kr = new self($path, [$record]);
        $kr->persist();
        return $kr;
    }

    public static function open(string $path): self
    {
        $raw = @file_get_contents($path);
        if ($raw === false) {
            throw new Exception('io', 'read keyring file');
        }
        return new self($path, self::decode($raw));
    }

    public function path(): string
    {
        return $this->path;
    }

    /** @return array{id:string,material:string} */
    public function currentFieldKey(string $database, string $table, string $column): array
    {
        foreach ($this->records as $r) {
            if ($r['current'] && !$r['revoked']) {
                return ['id' => $r['id'], 'material' => $r['material']];
            }
        }
        throw new Exception('crypto', 'current field key unavailable');
    }

    /** @return array{id:string,material:string} */
    public function fieldKey(string $database, string $table, string $column, string $keyID): array
    {
        foreach ($this->records as $r) {
            if ($r['id'] === $keyID) {
                if ($r['revoked']) {
                    throw new Exception('crypto', 'field key unavailable or revoked');
                }
                return ['id' => $r['id'], 'material' => $r['material']];
            }
        }
        throw new Exception('crypto', 'field key unavailable or revoked');
    }

    /**
     * Makes key current, retaining every other live key for overlap reads,
     * and persists atomically. Reusing a previously revoked key id fails
     * closed: a revoked id can never resolve again.
     *
     * @param array{id:string,material:string} $key
     */
    public function rotate(array $key): void
    {
        FieldEncryption::validateKey($key);
        $idx = null;
        foreach ($this->records as $i => $r) {
            if ($r['id'] === $key['id']) {
                $idx = $i;
                break;
            }
        }
        if ($idx !== null && $this->records[$idx]['revoked']) {
            throw new Exception('conflict', 'cannot reuse a revoked field key id');
        }
        if ($idx === null) {
            if (count($this->records) >= self::MAX_KEYS) {
                throw new Exception('exhausted', 'field key limit reached');
            }
            $this->records[] = [
                'id' => $key['id'],
                'created' => time(),
                'current' => false,
                'revoked' => false,
                'material' => $key['material'],
            ];
            $idx = count($this->records) - 1;
        }
        foreach (array_keys($this->records) as $i) {
            $this->records[$i]['current'] = false;
        }
        $this->records[$idx]['current'] = true;
        $this->records[$idx]['material'] = $key['material'];
        $this->persist();
    }

    /**
     * Destroys keyID's material on disk and marks it permanently refused.
     * The current key cannot be revoked directly; rotate away from it first.
     */
    public function revoke(string $keyID): void
    {
        $idx = null;
        foreach ($this->records as $i => $r) {
            if ($r['id'] === $keyID) {
                $idx = $i;
                break;
            }
        }
        if ($idx === null) {
            throw new Exception('not_found', 'unknown field key id');
        }
        if ($this->records[$idx]['current']) {
            throw new Exception('conflict', 'cannot revoke the current field key');
        }
        if ($this->records[$idx]['revoked']) {
            return;
        }
        $this->records[$idx]['revoked'] = true;
        $this->records[$idx]['material'] = str_repeat("\x00", 32);
        $this->persist();
    }

    /** Re-reads the keyring file. On any error the in-memory keyring is left unchanged (last known good). */
    public function reload(): void
    {
        $raw = @file_get_contents($this->path);
        if ($raw === false) {
            throw new Exception('io', 'read keyring file');
        }
        $this->records = self::decode($raw);
    }

    /** @return array{id:string,created:int,current:bool,revoked:bool}[] */
    public function list(): array
    {
        return array_map(
            static fn (array $r): array => [
                'id' => $r['id'],
                'created' => $r['created'],
                'current' => $r['current'],
                'revoked' => $r['revoked'],
            ],
            $this->records
        );
    }

    private function persist(): void
    {
        $raw = self::encode($this->records);
        $tmp = $this->path . '.tmp';
        if (file_put_contents($tmp, $raw) === false) {
            throw new Exception('io', 'write keyring file');
        }
        chmod($tmp, 0600);
        if (!rename($tmp, $this->path)) {
            @unlink($tmp);
            throw new Exception('io', 'rename keyring file');
        }
    }

    /** @param array{id:string,created:int,current:bool,revoked:bool,material:string}[] $records */
    private static function encode(array $records): string
    {
        if (count($records) > self::MAX_KEYS) {
            throw new Exception('invalid_argument', 'too many field keys');
        }
        $out = self::MAGIC . pack('v', self::VERSION) . pack('v', count($records));
        foreach ($records as $r) {
            if (!self::validKeyID($r['id'])) {
                throw new Exception('invalid_format', 'invalid field key id length');
            }
            if (strlen($r['material']) !== 32) {
                throw new Exception('invalid_format', 'invalid field key material size');
            }
            $flags = 0;
            if ($r['current']) {
                $flags |= self::FLAG_CURRENT;
            }
            if ($r['revoked']) {
                $flags |= self::FLAG_REVOKED;
            }
            $out .= chr(strlen($r['id'])) . $r['id'] . self::packU64($r['created']) . chr($flags) . $r['material'];
        }
        return $out;
    }

    /** @return array{id:string,created:int,current:bool,revoked:bool,material:string}[] */
    private static function decode(string $raw): array
    {
        $bad = static function (string $msg): never {
            throw new Exception('invalid_format', $msg);
        };
        if (strlen($raw) < 8) {
            $bad('truncated keyring');
        }
        if (substr($raw, 0, 4) !== self::MAGIC) {
            $bad('bad keyring magic');
        }
        $version = unpack('v', substr($raw, 4, 2));
        if ($version === false || $version[1] !== self::VERSION) {
            $bad('unsupported keyring version');
        }
        $countArr = unpack('v', substr($raw, 6, 2));
        if ($countArr === false) {
            $bad('truncated keyring');
        }
        $count = $countArr[1];
        if ($count > self::MAX_KEYS) {
            $bad('key count exceeds limit');
        }
        $records = [];
        $seen = [];
        $off = 8;
        $currentCount = 0;
        for ($i = 0; $i < $count; $i++) {
            if ($off >= strlen($raw)) {
                $bad('truncated id length');
            }
            $idLen = ord($raw[$off]);
            $off += 1;
            if ($idLen < 1 || $idLen > self::MAX_KEY_ID) {
                $bad('invalid field key id length');
            }
            if ($off + $idLen > strlen($raw)) {
                $bad('truncated field key id');
            }
            $id = substr($raw, $off, $idLen);
            $off += $idLen;
            if (!self::validKeyID($id)) {
                $bad('invalid field key id');
            }
            if ($off + 8 > strlen($raw)) {
                $bad('truncated created time');
            }
            $created = self::unpackU64(substr($raw, $off, 8));
            $off += 8;
            if ($off >= strlen($raw)) {
                $bad('truncated flags');
            }
            $flags = ord($raw[$off]);
            $off += 1;
            if ($off + 32 > strlen($raw)) {
                $bad('truncated field key material');
            }
            $material = substr($raw, $off, 32);
            $off += 32;
            if (isset($seen[$id])) {
                $bad('duplicate field key id');
            }
            $seen[$id] = true;
            $current = ($flags & self::FLAG_CURRENT) !== 0;
            $revoked = ($flags & self::FLAG_REVOKED) !== 0;
            if ($current && $revoked) {
                $bad('current field key cannot be revoked');
            }
            $allZero = $material === str_repeat("\x00", 32);
            if ($revoked) {
                if (!$allZero) {
                    $bad('revoked field key retains material');
                }
            } elseif ($allZero) {
                $bad('empty field key material');
            }
            if ($current) {
                $currentCount++;
            }
            $records[] = [
                'id' => $id,
                'created' => $created,
                'current' => $current,
                'revoked' => $revoked,
                'material' => $material,
            ];
        }
        if ($off !== strlen($raw)) {
            $bad('trailing keyring bytes');
        }
        if (count($records) === 0) {
            $bad('keyring has no keys');
        }
        if ($currentCount !== 1) {
            $bad('keyring must have exactly one current key');
        }
        return $records;
    }

    private static function packU64(int $n): string
    {
        return pack('V', $n & 0xFFFFFFFF) . pack('V', ($n >> 32) & 0xFFFFFFFF);
    }

    private static function unpackU64(string $b): int
    {
        $lo = unpack('V', substr($b, 0, 4));
        $hi = unpack('V', substr($b, 4, 4));
        return $lo[1] + $hi[1] * (1 << 32);
    }

    private static function validKeyID(string $id): bool
    {
        return strlen($id) >= 1 && strlen($id) <= self::MAX_KEY_ID && preg_match('/^[A-Za-z0-9._-]+$/D', $id) === 1;
    }
}
