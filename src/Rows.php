<?php

declare(strict_types=1);

namespace NextSQL;

/**
 * @implements \IteratorAggregate<int, list<mixed>>
 */
final class Rows implements \IteratorAggregate
{
    /** @var list<string> */
    public array $columns = [];
    public int $affected = 0;

    /** @var list<list<mixed>> */
    private array $batch = [];
    private int $i = 0;
    private bool $done = false;
    private bool $closed = false;
    private ?Exception $err = null;

    /**
     * @param list<array{name:string,kind?:int}> $cols
     */
    public function __construct(private Client $conn, array $cols)
    {
        foreach ($cols as $c) {
            $this->columns[] = $c['name'];
        }
        if ($cols === []) {
            $this->done = true;
        }
    }

    public function next(): bool
    {
        if ($this->closed || $this->err !== null) {
            return false;
        }
        if ($this->i < count($this->batch)) {
            $this->i++;
            return true;
        }
        if ($this->done) {
            return false;
        }
        try {
            $this->fill();
        } catch (Exception $e) {
            $this->err = $e;
            return false;
        }
        if ($this->i < count($this->batch)) {
            $this->i++;
            return true;
        }
        return false;
    }

    /**
     * @return list<mixed>|null
     */
    public function values(): ?array
    {
        if ($this->i <= 0 || $this->i > count($this->batch)) {
            return null;
        }
        return $this->batch[$this->i - 1];
    }

    public function err(): ?Exception
    {
        return $this->err;
    }

    public function close(): void
    {
        while ($this->next()) {
        }
        if (!$this->closed) {
            $this->finish();
        }
        if ($this->err !== null) {
            throw $this->err;
        }
    }

    public function markClosed(): void
    {
        $this->closed = true;
        $this->done = true;
    }

    /**
     * @return array{columns: list<string>, rows: list<list<mixed>>, affected: int}
     */
    public function collect(): array
    {
        $out = [];
        try {
            while ($this->next()) {
                $out[] = $this->values();
            }
            if ($this->err !== null) {
                throw $this->err;
            }
        } finally {
            if (!$this->closed) {
                $this->close();
            }
        }
        return ['columns' => $this->columns, 'rows' => $out, 'affected' => $this->affected];
    }

    /**
     * @return \Traversable<int, list<mixed>>
     */
    public function getIterator(): \Traversable
    {
        try {
            while ($this->next()) {
                $row = $this->values();
                if ($row !== null) {
                    yield $row;
                }
            }
            if ($this->err !== null) {
                throw $this->err;
            }
        } finally {
            if (!$this->closed) {
                try {
                    $this->close();
                } catch (\Throwable) {
                }
            }
        }
    }

    private function fill(): void
    {
        if (!$this->done && $this->batch !== []) {
            $this->conn->writeFrame(Client::TYPE_FLOW_ACK, '');
        }
        $msg = $this->conn->readFrame();
        if ($msg['type'] === Client::TYPE_DATA_BATCH) {
            $this->batch = Protocol::decodeDataBatch($msg['payload']);
            $this->i = 0;
            return;
        }
        if ($msg['type'] === Client::TYPE_COMMAND_COMPLETE) {
            $this->affected = Protocol::decodeCommandComplete($msg['payload']);
            $this->done = true;
            $this->batch = [];
            $this->i = 0;
            $this->conn->expectReady();
            $this->finish();
            return;
        }
        throw $this->conn->unexpected($msg);
    }

    private function finish(): void
    {
        if (!$this->closed) {
            $this->conn->releaseBusy();
        }
        $this->closed = true;
    }
}
