<?php

declare(strict_types=1);

namespace NextSQL;

/** Bounded, non-durable in-process provider for already-loaded field keys. */
final class MemoryFieldKeyring implements FieldKeyProvider
{
    private const MAX_KEYS = 64;
    private string $current;
    /** @var array<string, array{id:string,material:string}> */
    private array $keys = [];

    /** @param array{id:string,material:string} $current @param array{id:string,material:string} ...$overlap */
    public function __construct(array $current, array ...$overlap)
    {
        $all = [$current, ...$overlap];
        if (count($all) > self::MAX_KEYS) {
            throw new Exception('invalid_argument', 'too many field keys');
        }
        foreach ($all as $key) {
            FieldEncryption::validateKey($key);
            if (isset($this->keys[$key['id']])) {
                throw new Exception('invalid_argument', 'duplicate field key id');
            }
            $this->keys[$key['id']] = ['id' => $key['id'], 'material' => $key['material']];
        }
        $this->current = $current['id'];
    }

    public function currentFieldKey(string $database, string $table, string $column): array
    {
        if (!isset($this->keys[$this->current])) {
            throw new Exception('crypto', 'current field key unavailable');
        }
        return $this->keys[$this->current];
    }

    public function fieldKey(string $database, string $table, string $column, string $keyID): array
    {
        if (!isset($this->keys[$keyID])) {
            throw new Exception('crypto', 'field key unavailable or revoked');
        }
        return $this->keys[$keyID];
    }

    /** @param array{id:string,material:string} $key */
    public function rotate(array $key): void
    {
        FieldEncryption::validateKey($key);
        if (!isset($this->keys[$key['id']]) && count($this->keys) >= self::MAX_KEYS) {
            throw new Exception('exhausted', 'field key limit reached');
        }
        $this->keys[$key['id']] = ['id' => $key['id'], 'material' => $key['material']];
        $this->current = $key['id'];
    }

    public function revoke(string $keyID): void
    {
        if ($keyID === $this->current) {
            throw new Exception('conflict', 'cannot revoke current field key');
        }
        unset($this->keys[$keyID]);
    }
}
