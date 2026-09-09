<?php

declare(strict_types=1);

namespace NextSQL;

final class Exception extends \RuntimeException
{
    /**
     * $publicCode is the stable ERR_* name from docs/error-codes.md. It is set
     * only on an error received over a connection that negotiated the public
     * taxonomy, and is '' otherwise -- for a local error, or an older server.
     * $errorCode always carries the legacy class, so retry logic keeps reading
     * that and nothing should require $publicCode.
     */
    public function __construct(
        public readonly string $errorCode,
        string $message = '',
        int $code = 0,
        ?\Throwable $previous = null,
        public readonly string $publicCode = '',
    ) {
        parent::__construct($message !== '' ? $message : $errorCode, $code, $previous);
    }
}
