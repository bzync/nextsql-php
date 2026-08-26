<?php

declare(strict_types=1);

namespace NextSQL;

final class Exception extends \RuntimeException
{
    public function __construct(
        public readonly string $errorCode,
        string $message = '',
        int $code = 0,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message !== '' ? $message : $errorCode, $code, $previous);
    }
}
