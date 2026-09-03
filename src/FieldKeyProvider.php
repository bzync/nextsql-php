<?php

declare(strict_types=1);

namespace NextSQL;

/** Client-only key provider for ENCRYPTED CLIENT columns. */
interface FieldKeyProvider
{
    /** @return array{id:string,material:string} material is exactly 32 binary bytes */
    public function currentFieldKey(string $database, string $table, string $column): array;

    /** @return array{id:string,material:string} material is exactly 32 binary bytes */
    public function fieldKey(string $database, string $table, string $column, string $keyID): array;
}
