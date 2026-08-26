<?php

declare(strict_types=1);

namespace NextSQL;

final class Statement
{
    public function __construct(private Client $conn, private int $id)
    {
    }

    /**
     * @param list<mixed> $params
     */
    public function query(array $params = []): Rows
    {
        return $this->conn->executePrepared($this->id, $params);
    }

    /**
     * @param list<mixed> $params
     * @return array{columns: list<string>, rows: list<list<mixed>>, affected: int}
     */
    public function exec(array $params = []): array
    {
        return $this->query($params)->collect();
    }

    public function close(): void
    {
        if ($this->id === 0) {
            return;
        }
        $this->conn->closeStatement($this->id);
        $this->id = 0;
    }
}
