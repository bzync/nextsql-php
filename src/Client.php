<?php

declare(strict_types=1);

namespace NextSQL;

/**
 * Official NextSQL PHP driver. Speaks the native NSQL v1 protocol.
 * Encryption keys and passwords are never accepted in a URL.
 */
final class Client
{
    public const VERSION = 1;
    public const MAX_PACKET = 1 << 20;
    public const MAX_SQL = 1 << 20;
    public const MAX_NAME = 256;
    public const MAX_PARAMS = 256;
    public const MAX_ENUM_LABELS = 4096;
    public const MAX_ENUM_LABEL_BYTES = 255;

    public const TYPE_HELLO = 1;
    public const TYPE_HELLO_OK = 2;
    public const TYPE_AUTH = 3;
    public const TYPE_AUTH_OK = 4;
    public const TYPE_QUERY = 5;
    public const TYPE_PREPARE = 6;
    public const TYPE_PREPARE_OK = 7;
    public const TYPE_EXECUTE = 8;
    public const TYPE_CLOSE_STMT = 9;
    public const TYPE_CLOSE_OK = 10;
    public const TYPE_FLOW_ACK = 11;
    public const TYPE_CANCEL = 12;
    public const TYPE_TERMINATE = 13;
    public const TYPE_ROW_DESC = 14;
    public const TYPE_DATA_BATCH = 15;
    public const TYPE_COMMAND_COMPLETE = 16;
    public const TYPE_ERROR = 17;
    public const TYPE_READY = 18;
    public const TYPE_UNLOCK = 19;
    public const TYPE_UNLOCK_OK = 20;
    public const TYPE_IDEMPOTENT_QUERY = 21;
    public const TYPE_SET_READ_CONSISTENCY = 22;
    public const TYPE_NODE_STATUS = 23;
    public const TYPE_NODE_STATUS_RESP = 24;

    /** Read-consistency modes. Values match the wire byte ordering. */
    public const READ_STRONG = 0;
    public const READ_BOUNDED = 1;
    public const READ_STALE = 2;

    public const AUTH_PASSWORD = 1;
    public const AUTH_PASSWORD_KEY = 2;
    public const FLAG_CANCEL = 1;
    public const FLAG_NULL = 0x01;

    public const KIND_UUID = 1;
    public const KIND_STRING = 2;
    public const KIND_TEXT = 3;
    public const KIND_DECIMAL = 4;
    public const KIND_TIMESTAMPTZ = 5;
    public const KIND_JSON = 6;
    public const KIND_VECTOR = 7;
    public const KIND_BOOL = 8;
    public const KIND_NULL = 9;
    public const KIND_POINT = 10;
    public const KIND_BOX = 11;
    public const KIND_LINE = 12;
    public const KIND_POLYGON = 13;
    public const KIND_BLOB = 14;
    public const KIND_INT8 = 15;
    public const KIND_INT16 = 16;
    public const KIND_INT32 = 17;
    public const KIND_INT64 = 18;
    public const KIND_UINT8 = 19;
    public const KIND_UINT16 = 20;
    public const KIND_UINT32 = 21;
    public const KIND_UINT64 = 22;
    public const KIND_DATE = 23;
    public const KIND_TIME = 24;
    public const KIND_CHAR = 25;
    public const KIND_VARCHAR = 26;
    public const KIND_TIMESTAMP = 27;
    public const KIND_FLOAT32 = 28;
    public const KIND_FLOAT64 = 29;
    public const KIND_ENUM = 30;
    public const KIND_INTERVAL = 31;
    public const KIND_STRUCT = 32;
    public const KIND_ARRAY = 33;
    public const KIND_MAP = 34;
    public const KIND_GEOMETRY = 35;
    public const KIND_GEOGRAPHY = 36;
    public const MAX_NEST_DEPTH = 8;
    public const MAX_STRUCT_FIELDS = 128;
    public const MAX_COLLECTION_LEN = 1048576;

    /** @var resource */
    private $sock;
    /** @var array<string, mixed> */
    private array $cfg;
    private string $secret = '';
    private bool $busy = false;

    /**
     * @param array<string, mixed> $cfg
     */
    public static function connect(array $cfg): self
    {
        self::validateConfig($cfg);
        $sock = self::dial($cfg);
        $c = new self($cfg, $sock);
        try {
            $c->handshake();
            $mode = $cfg['readConsistency'] ?? self::READ_STRONG;
            if ((int) $mode !== self::READ_STRONG) {
                $c->setReadConsistency((int) $mode, (int) ($cfg['maxStalenessMs'] ?? 0));
            }
        } catch (\Throwable $e) {
            fclose($sock);
            throw $e;
        }
        return $c;
    }

    /**
     * setReadConsistency sets this connection's read-consistency mode for
     * subsequent statements. $maxStalenessMs applies only to BOUNDED (0 selects
     * the server default window).
     */
    public function setReadConsistency(int $mode, int $maxStalenessMs = 0): void
    {
        if ($this->busy) {
            throw new Exception('conflict', 'connection is busy');
        }
        $this->writeFrame(self::TYPE_SET_READ_CONSISTENCY, Protocol::encodeSetReadConsistency($mode, $maxStalenessMs));
        $this->readAck();
    }

    /**
     * nodeStatus asks the connected server for its key-free replication health.
     *
     * @return array{role:string,hasLeader:bool,healthy:bool,appliedLSN:int,lastContactMs:int,applyBacklog:int}
     */
    public function nodeStatus(): array
    {
        if ($this->busy) {
            throw new Exception('conflict', 'connection is busy');
        }
        $this->writeFrame(self::TYPE_NODE_STATUS, '');
        $msg = $this->readFrame();
        if ($msg['type'] !== self::TYPE_NODE_STATUS_RESP) {
            throw $this->unexpected($msg);
        }
        $st = Protocol::decodeNodeStatus($msg['payload']);
        $this->expectReady();
        return $st;
    }

    /**
     * readAck reads a single control acknowledgement: Ready, or Error
     * (unexpected() drains the trailing Ready so the session stays usable).
     */
    private function readAck(): void
    {
        $msg = $this->readFrame();
        if ($msg['type'] === self::TYPE_READY) {
            return;
        }
        throw $this->unexpected($msg);
    }

    /** txnControl reports whether $sql opens or closes an explicit transaction. */
    public static function txnControl(string $sql): array
    {
        $up = strtoupper(ltrim($sql, " \t\r\n("));
        $begin = str_starts_with($up, 'BEGIN') || str_starts_with($up, 'START TRANSACTION');
        $end = str_starts_with($up, 'COMMIT') || str_starts_with($up, 'ROLLBACK');
        return ['begin' => $begin, 'end' => $end];
    }

    /**
     * isReadOnlySQL is a conservative check: a false negative only costs a
     * leader round trip, and a false positive self-corrects on the leader.
     * EXPLAIN is excluded because EXPLAIN ANALYZE executes its statement.
     */
    public static function isReadOnlySQL(string $sql): bool
    {
        $s = ltrim($sql, " \t\r\n(");
        while (str_starts_with($s, '--')) {
            $i = strpos($s, "\n");
            if ($i === false) {
                return false;
            }
            $s = ltrim(substr($s, $i + 1), " \t\r\n(");
        }
        $up = strtoupper($s);
        if (str_starts_with($up, 'SELECT') || str_starts_with($up, 'SHOW')) {
            return true;
        }
        if (str_starts_with($up, 'WITH')) {
            return !str_contains($up, 'INSERT') && !str_contains($up, 'UPDATE')
                && !str_contains($up, 'DELETE') && !str_contains($up, 'UPSERT');
        }
        return false;
    }

    /**
     * @param array<string, mixed> $cfg
     */
    public static function validateConfig(array $cfg): void
    {
        if (!isset($cfg['address']) || $cfg['address'] === '') {
            throw new Exception('invalid_argument', 'address is required');
        }
        $addr = strtolower((string) $cfg['address']);
        if (str_contains($addr, '://') || str_contains($addr, 'key=') || str_contains($addr, 'password=')) {
            throw new Exception('invalid_argument', 'keys and credentials must not be passed in a URL');
        }
        if (empty($cfg['tls']) && empty($cfg['insecureNoTLS'])) {
            throw new Exception('invalid_argument', 'TLS is required for remote connections');
        }
        if (!empty($cfg['insecureNoTLS']) && !self::isLoopback((string) $cfg['address'])) {
            throw new Exception('invalid_argument', 'plaintext is only allowed on loopback');
        }
        if (empty($cfg['user'])) {
            throw new Exception('invalid_argument', 'user is required');
        }
    }

    public static function isLoopback(string $addr): bool
    {
        [$host] = self::splitHostPort($addr, true);
        $host = strtolower(trim($host));
        if ($host === 'localhost') {
            return true;
        }
        if ($host === '::1' || $host === '0:0:0:0:0:0:0:1') {
            return true;
        }
        return (bool) preg_match('/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/', $host);
    }

    /**
     * @return array{0:string,1:int}
     */
    public static function splitHostPort(string $addr, bool $allowBare = false): array
    {
        if ($addr !== '' && $addr[0] === '[') {
            $end = strpos($addr, ']');
            if ($end === false) {
                throw new Exception('invalid_argument', 'invalid address');
            }
            $host = substr($addr, 1, $end - 1);
            if (isset($addr[$end + 1]) && $addr[$end + 1] === ':') {
                return [$host, (int) substr($addr, $end + 2)];
            }
            if ($allowBare) {
                return [$host, 0];
            }
            throw new Exception('invalid_argument', 'address requires a port');
        }
        $i = strrpos($addr, ':');
        if ($i === false) {
            if ($allowBare) {
                return [$addr, 0];
            }
            throw new Exception('invalid_argument', 'address requires a port');
        }
        return [substr($addr, 0, $i), (int) substr($addr, $i + 1)];
    }

    /**
     * @param array<string, mixed> $cfg
     * @param resource $sock
     */
    private function __construct(array $cfg, $sock)
    {
        $this->cfg = $cfg;
        $this->sock = $sock;
    }

    /**
     * @param array<string, mixed> $cfg
     * @return resource
     */
    private static function dial(array $cfg)
    {
        [$host, $port] = self::splitHostPort((string) $cfg['address']);
        $target = str_contains($host, ':') ? "tcp://[$host]:$port" : "tcp://$host:$port";
        $errno = 0;
        $errstr = '';
        $tmp = null;
        $ctx = null;
        if (!empty($cfg['tls'])) {
            if (!defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT')) {
                throw new Exception('protocol', 'PHP TLS 1.3 is required');
            }
            $tls = is_array($cfg['tls']) ? $cfg['tls'] : [];
            $crypto = [
                'crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT,
                'peer_name' => $tls['servername'] ?? $host,
                'verify_peer' => ($tls['rejectUnauthorized'] ?? true) !== false,
                'verify_peer_name' => ($tls['rejectUnauthorized'] ?? true) !== false,
                'disable_compression' => true,
            ];
            if (!empty($tls['ca'])) {
                $tmp = tempnam(sys_get_temp_dir(), 'nsqlca');
                if ($tmp === false || file_put_contents($tmp, $tls['ca']) === false) {
                    throw new Exception('io', 'could not write CA file');
                }
                $crypto['cafile'] = $tmp;
            } elseif (!empty($tls['cafile'])) {
                $crypto['cafile'] = $tls['cafile'];
            }
            $ctx = stream_context_create(['ssl' => $crypto]);
        }
        $sock = $ctx === null
            ? @stream_socket_client($target, $errno, $errstr, 10.0, STREAM_CLIENT_CONNECT)
            : @stream_socket_client($target, $errno, $errstr, 10.0, STREAM_CLIENT_CONNECT, $ctx);
        if ($sock === false) {
            if ($tmp !== null) {
                @unlink($tmp);
            }
            throw new Exception('io', $errstr !== '' ? $errstr : 'dial failed');
        }
        stream_set_timeout($sock, 60);
        if ($ctx !== null) {
            $ok = @stream_socket_enable_crypto($sock, true, STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT);
            if ($tmp !== null) {
                @unlink($tmp);
            }
            if ($ok !== true) {
                fclose($sock);
                throw new Exception('protocol', 'tls handshake');
            }
        }
        return $sock;
    }

    private function handshake(): void
    {
        $this->writeFrame(self::TYPE_HELLO, Protocol::encodeHello([
            'version' => self::VERSION,
            'flags' => 0,
            'secret' => "\x00\x00\x00\x00\x00\x00\x00\x00",
            'database' => (string) ($this->cfg['database'] ?? ''),
            'user' => (string) $this->cfg['user'],
            'realm' => (string) ($this->cfg['realm'] ?? ''),
        ]));
        $msg = $this->readFrame();
        if ($msg['type'] !== self::TYPE_HELLO_OK) {
            throw $this->unexpected($msg);
        }
        $ok = Protocol::decodeHelloOK($msg['payload']);
        $this->secret = $ok['secret'];
        $this->writeFrame(self::TYPE_AUTH, Protocol::u16str((string) ($this->cfg['password'] ?? '')));
        $msg = $this->readFrame();
        if ($msg['type'] !== self::TYPE_AUTH_OK) {
            throw $this->unexpected($msg);
        }
        if ($ok['authMethod'] === self::AUTH_PASSWORD_KEY) {
            $key = $this->cfg['key'] ?? null;
            if (!is_string($key) || strlen($key) !== 32) {
                throw new Exception('unauthorized', 'server requires a client-held key');
            }
            $ver = (int) ($this->cfg['keyVersion'] ?? 1);
            $mat = Protocol::u32le($ver) . $key;
            $this->writeFrame(self::TYPE_UNLOCK, $mat);
            $msg = $this->readFrame();
            if ($msg['type'] !== self::TYPE_UNLOCK_OK) {
                throw $this->unexpected($msg);
            }
        }
        $msg = $this->readFrame();
        if ($msg['type'] !== self::TYPE_READY) {
            throw $this->unexpected($msg);
        }
    }

    /**
     * @param list<mixed> $params
     * @return array{columns: list<string>, rows: list<list<mixed>>, affected: int}
     */
    public function exec(string $sql, array $params = []): array
    {
        $rows = $this->query($sql, $params);
        return $rows->collect();
    }

    /** Seal a logical value into the opaque STRING accepted by ENCRYPTED CLIENT. */
    public function encryptField(string $table, string $column, array $type, mixed $value): ?string
    {
        $provider = $this->cfg['fieldKeys'] ?? null;
        if (!$provider instanceof FieldKeyProvider) {
            throw new Exception('invalid_argument', 'field key provider is required');
        }
        return FieldEncryption::encrypt($provider, (string) ($this->cfg['database'] ?? ''), $table, $column, $type, $value);
    }

    /** Authenticate and decode one opaque ENCRYPTED CLIENT result. */
    public function decryptField(string $table, string $column, array $type, ?string $ciphertext): mixed
    {
        $provider = $this->cfg['fieldKeys'] ?? null;
        if (!$provider instanceof FieldKeyProvider) {
            throw new Exception('invalid_argument', 'field key provider is required');
        }
        return FieldEncryption::decrypt($provider, (string) ($this->cfg['database'] ?? ''), $table, $column, $type, $ciphertext);
    }

    /**
     * @param list<mixed> $params
     */
    public function query(string $sql, array $params = []): Rows
    {
        if (!is_resource($this->sock)) {
            throw new Exception('unavailable', 'connection closed');
        }
        if ($this->busy) {
            throw new Exception('conflict', 'connection is busy');
        }
        $this->busy = true;
        try {
            $this->writeFrame(self::TYPE_QUERY, Protocol::encodeQuery($sql, $params));
            return $this->readRows();
        } catch (\Throwable $e) {
            $this->busy = false;
            throw $e;
        }
    }

    public function prepare(string $sql): Statement
    {
        if ($this->busy) {
            throw new Exception('conflict', 'connection is busy');
        }
        $this->writeFrame(self::TYPE_PREPARE, Protocol::u32bytes($sql, self::MAX_SQL));
        $msg = $this->readFrame();
        if ($msg['type'] !== self::TYPE_PREPARE_OK) {
            throw $this->unexpected($msg);
        }
        if (strlen($msg['payload']) !== 4) {
            throw new Exception('protocol', 'bad prepare-ok length');
        }
        $id = Protocol::u32($msg['payload'], 0);
        $this->expectReady();
        return new Statement($this, $id);
    }

    /**
     * @param list<mixed> $params
     */
    public function executePrepared(int $id, array $params): Rows
    {
        if ($this->busy) {
            throw new Exception('conflict', 'connection is busy');
        }
        $this->busy = true;
        try {
            $this->writeFrame(self::TYPE_EXECUTE, Protocol::encodeExecute($id, $params));
            return $this->readRows();
        } catch (\Throwable $e) {
            $this->busy = false;
            throw $e;
        }
    }

    public function closeStatement(int $id): void
    {
        if ($this->busy) {
            throw new Exception('conflict', 'connection is busy');
        }
        $this->writeFrame(self::TYPE_CLOSE_STMT, Protocol::u32le($id));
        $msg = $this->readFrame();
        if ($msg['type'] !== self::TYPE_CLOSE_OK) {
            throw $this->unexpected($msg);
        }
        $this->expectReady();
    }

    public function cancel(): void
    {
        if ($this->secret === '') {
            throw new Exception('unavailable', 'not connected');
        }
        $side = self::dial($this->cfg);
        try {
            $tmp = new self($this->cfg, $side);
            $tmp->writeFrame(self::TYPE_HELLO, Protocol::encodeHello([
                'version' => self::VERSION,
                'flags' => self::FLAG_CANCEL,
                'secret' => $this->secret,
                'database' => '',
                'user' => '',
            ]));
            $msg = $tmp->readFrame();
            if ($msg['type'] !== self::TYPE_READY) {
                throw $this->unexpected($msg);
            }
        } finally {
            fclose($side);
        }
    }

    public function close(): void
    {
        if (!is_resource($this->sock)) {
            return;
        }
        try {
            $this->writeFrame(self::TYPE_TERMINATE, '');
        } catch (\Throwable) {
        }
        fclose($this->sock);
    }

    public function releaseBusy(): void
    {
        $this->busy = false;
    }

    /**
     * @return array{type: int, payload: string}
     */
    public function readFrame(): array
    {
        $hdr = $this->readExact(12);
        if (substr($hdr, 0, 4) !== 'NSQL') {
            throw new Exception('protocol', 'bad magic');
        }
        if (Protocol::u16($hdr, 4) !== self::VERSION) {
            throw new Exception('protocol', 'unsupported protocol version');
        }
        $typ = ord($hdr[6]);
        if ($typ === 0) {
            throw new Exception('protocol', 'invalid message type');
        }
        $n = Protocol::u32($hdr, 8);
        if ($n > self::MAX_PACKET) {
            throw new Exception('protocol', 'packet exceeds limit');
        }
        $payload = $n === 0 ? '' : $this->readExact($n);
        return ['type' => $typ, 'payload' => $payload];
    }

    public function writeFrame(int $type, string $payload): void
    {
        if (strlen($payload) > self::MAX_PACKET) {
            throw new Exception('protocol', 'payload exceeds packet limit');
        }
        $hdr = 'NSQL' . Protocol::u16le(self::VERSION) . chr($type) . "\x00" . Protocol::u32le(strlen($payload));
        $this->writeAll($hdr . $payload);
    }

    public function expectReady(): void
    {
        $msg = $this->readFrame();
        if ($msg['type'] !== self::TYPE_READY) {
            throw $this->unexpected($msg);
        }
    }

    /**
     * Decodes an out-of-band Error frame (or reports a genuine protocol
     * violation) for a call site checking "did I get what I expected?".
     * writeErrReady on the server always sends Error then Ready — every
     * call site funnels through here specifically so that trailing Ready
     * is always drained in one place, rather than each of
     * query/prepare/closeStatement/etc. having to remember to do it
     * individually (a per-call-site version of this was exactly the shape
     * of a real bug: readRows/prepare/closeStatement never drained it,
     * leaving the connection permanently desynced after the first query
     * error).
     *
     * @param array{type: int, payload: string} $msg
     */
    public function unexpected(array $msg): Exception
    {
        if ($msg['type'] === self::TYPE_ERROR) {
            $err = Protocol::decodeError($msg['payload']);
            try {
                $this->expectReady();
            } catch (\Throwable) {
                // Best-effort: surface the original application error even
                // if draining the trailing Ready itself fails (e.g. the
                // connection is now genuinely broken).
            }
            return $err;
        }
        return new Exception('protocol', 'unexpected message type');
    }

    private function readRows(): Rows
    {
        $msg = $this->readFrame();
        if ($msg['type'] === self::TYPE_ROW_DESC) {
            return new Rows($this, Protocol::decodeRowDesc($msg['payload']));
        }
        if ($msg['type'] === self::TYPE_COMMAND_COMPLETE) {
            $rows = new Rows($this, []);
            $rows->affected = Protocol::decodeCommandComplete($msg['payload']);
            $this->expectReady();
            $this->busy = false;
            $rows->markClosed();
            return $rows;
        }
        $this->busy = false;
        throw $this->unexpected($msg);
    }

    private function readExact(int $n): string
    {
        $out = '';
        while (strlen($out) < $n) {
            $chunk = fread($this->sock, $n - strlen($out));
            if ($chunk === false || $chunk === '') {
                throw new Exception('unavailable', 'connection closed');
            }
            $out .= $chunk;
        }
        return $out;
    }

    private function writeAll(string $data): void
    {
        $off = 0;
        $n = strlen($data);
        while ($off < $n) {
            $w = fwrite($this->sock, substr($data, $off));
            if ($w === false || $w === 0) {
                throw new Exception('io', 'write failed');
            }
            $off += $w;
        }
    }
}
