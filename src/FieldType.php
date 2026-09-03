<?php

declare(strict_types=1);

namespace NextSQL;

/** Logical type descriptors authenticated by the NSCE1 envelope. */
final class FieldType
{
    /** @return array{kind:int,precision:int,scale:int,vecElem:int} */
    public static function uuid(): array { return self::type(Client::KIND_UUID); }
    /** @return array{kind:int,precision:int,scale:int,vecElem:int} */
    public static function string(): array { return self::type(Client::KIND_STRING); }
    /** @return array{kind:int,precision:int,scale:int,vecElem:int} */
    public static function text(): array { return self::type(Client::KIND_TEXT); }
    /** @return array{kind:int,precision:int,scale:int,vecElem:int} */
    public static function timestampTZ(): array { return self::type(Client::KIND_TIMESTAMPTZ); }
    /** @return array{kind:int,precision:int,scale:int,vecElem:int} */
    public static function json(): array { return self::type(Client::KIND_JSON); }
    /** @return array{kind:int,precision:int,scale:int,vecElem:int} */
    public static function bool(): array { return self::type(Client::KIND_BOOL); }
    /** @return array{kind:int,precision:int,scale:int,vecElem:int} */
    public static function blob(): array { return self::type(Client::KIND_BLOB); }
    /** @return array{kind:int,precision:int,scale:int,vecElem:int} */
    public static function int8(): array { return self::type(Client::KIND_INT8); }
    /** @return array{kind:int,precision:int,scale:int,vecElem:int} */
    public static function int16(): array { return self::type(Client::KIND_INT16); }
    /** @return array{kind:int,precision:int,scale:int,vecElem:int} */
    public static function int32(): array { return self::type(Client::KIND_INT32); }
    /** @return array{kind:int,precision:int,scale:int,vecElem:int} */
    public static function int64(): array { return self::type(Client::KIND_INT64); }
    /** @return array{kind:int,precision:int,scale:int,vecElem:int} */
    public static function uint8(): array { return self::type(Client::KIND_UINT8); }
    /** @return array{kind:int,precision:int,scale:int,vecElem:int} */
    public static function uint16(): array { return self::type(Client::KIND_UINT16); }
    /** @return array{kind:int,precision:int,scale:int,vecElem:int} */
    public static function uint32(): array { return self::type(Client::KIND_UINT32); }
    /** @return array{kind:int,precision:int,scale:int,vecElem:int} */
    public static function uint64(): array { return self::type(Client::KIND_UINT64); }

    /** @return array{kind:int,precision:int,scale:int,vecElem:int} */
    public static function decimal(int $precision, int $scale): array
    {
        if ($precision < 1 || $precision > 38 || $scale < 0 || $scale > $precision) {
            throw new Exception('invalid_argument', 'DECIMAL precision/scale out of range');
        }
        return ['kind' => Client::KIND_DECIMAL, 'precision' => $precision, 'scale' => $scale, 'vecElem' => 0];
    }

    /** @return array{kind:int,precision:int,scale:int,vecElem:int} */
    private static function type(int $kind): array
    {
        return ['kind' => $kind, 'precision' => 0, 'scale' => 0, 'vecElem' => 0];
    }
}
