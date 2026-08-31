<?php

declare(strict_types=1);

namespace NextSQL;

/**
 * Cluster is a routing client over every node of a NextSQL HA cluster.
 *
 * With $cfg['readConsistency'] set to READ_BOUNDED or READ_STALE it sends
 * eligible read-only statements to a healthy follower and everything else —
 * writes, DDL, transaction control, and strong reads — to the leader. With the
 * default strong consistency every statement goes to the leader and Cluster is
 * just a leader-failover wrapper.
 *
 * A Cluster is for sequential use. Like Client, an open Rows pins its
 * connection until closed.
 */
final class Cluster
{
    /** Milliseconds a cached per-node status is trusted before a re-probe. */
    private const STATUS_TTL_MS = 500;

    /** @var list<array{addr:string,conn:Client,status:?array<string,mixed>,seen:float}> */
    private array $conns = [];
    private int $rr = 0;
    private bool $inTxn = false;
    private int $readConsistency;

    /**
     * @param array<string, mixed> $cfg
     */
    public static function connect(array $cfg): self
    {
        $addrs = [];
        if (isset($cfg['nodes']) && is_array($cfg['nodes']) && $cfg['nodes'] !== []) {
            $addrs = array_values($cfg['nodes']);
        } elseif (isset($cfg['address']) && $cfg['address'] !== '') {
            $addrs = [$cfg['address']];
        }
        if ($addrs === []) {
            throw new Exception('invalid_argument', 'at least one node address is required');
        }
        foreach ($addrs as $a) {
            Client::validateConfig(['address' => $a] + array_diff_key($cfg, ['nodes' => 1]));
        }

        $self = new self();
        $self->readConsistency = (int) ($cfg['readConsistency'] ?? Client::READ_STRONG);
        $first = null;
        foreach ($addrs as $a) {
            $nc = $cfg;
            $nc['address'] = $a;
            unset($nc['nodes']);
            try {
                $self->conns[] = ['addr' => (string) $a, 'conn' => Client::connect($nc), 'status' => null, 'seen' => 0.0];
            } catch (\Throwable $e) {
                $first ??= $e;
            }
        }
        if ($self->conns === []) {
            throw $first ?? new Exception('unavailable', 'no reachable node');
        }
        return $self;
    }

    private function __construct()
    {
    }

    public function close(): void
    {
        foreach ($this->conns as $cc) {
            $cc['conn']->close();
        }
    }

    /**
     * @return list<array<string,mixed>>
     */
    public function nodes(): array
    {
        $this->refresh();
        $out = [];
        foreach ($this->conns as $cc) {
            if ($cc['status'] !== null) {
                $out[] = $cc['status'];
            }
        }
        return $out;
    }

    /**
     * @param list<mixed> $params
     * @return array{columns: list<string>, rows: list<list<mixed>>, affected: int}
     */
    public function exec(string $sql, array $params = []): array
    {
        return $this->query($sql, $params)->collect();
    }

    /**
     * @param list<mixed> $params
     */
    public function query(string $sql, array $params = []): Rows
    {
        $tc = Client::txnControl($sql);
        $routable = !$this->inTxn && !$tc['begin'] && !$tc['end']
            && $this->readConsistency !== Client::READ_STRONG
            && Client::isReadOnlySQL($sql);

        if ($routable) {
            $fc = $this->followerConn();
            if ($fc !== null) {
                try {
                    return $fc->query($sql, $params);
                } catch (Exception $e) {
                    if ($e->errorCode !== 'unavailable') {
                        throw $e;
                    }
                    // Follower lost the leader or fell outside the bound; the
                    // leader can always answer, so fall through.
                }
            }
        }

        $rows = $this->leaderConn()->query($sql, $params);
        if ($tc['begin'] || $tc['end']) {
            $this->inTxn = $tc['begin'];
        }
        return $rows;
    }

    private function refresh(): void
    {
        $now = microtime(true) * 1000;
        foreach ($this->conns as $k => $cc) {
            if ($now - $cc['seen'] < self::STATUS_TTL_MS) {
                continue;
            }
            try {
                $this->conns[$k]['status'] = $cc['conn']->nodeStatus();
                $this->conns[$k]['seen'] = microtime(true) * 1000;
            } catch (\Throwable) {
                // keep the last known status
            }
        }
    }

    private function leaderConn(): Client
    {
        $this->refresh();
        foreach ($this->conns as $cc) {
            $role = $cc['status']['role'] ?? null;
            if ($role === 'leader' || $role === 'standalone') {
                return $cc['conn'];
            }
        }
        throw new Exception('unavailable', 'no reachable leader');
    }

    private function followerConn(): ?Client
    {
        $this->refresh();
        $followers = [];
        $others = [];
        foreach ($this->conns as $cc) {
            if (($cc['status']['healthy'] ?? false) !== true) {
                continue;
            }
            $role = $cc['status']['role'] ?? null;
            if ($role === 'follower') {
                $followers[] = $cc['conn'];
            } elseif ($role === 'leader' || $role === 'standalone') {
                $others[] = $cc['conn'];
            }
        }
        $pick = $followers !== [] ? $followers : $others;
        if ($pick === []) {
            return null;
        }
        $conn = $pick[$this->rr % count($pick)];
        $this->rr++;
        return $conn;
    }
}
