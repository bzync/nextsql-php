<?php

declare(strict_types=1);

require dirname(__DIR__) . '/autoload.php';

use NextSQL\Client;

$addr = getenv('NEXTSQL_ADDR');
$ca = getenv('NEXTSQL_CA');
if ($addr === false || $ca === false || $addr === '' || $ca === '') {
    fwrite(STDERR, "NEXTSQL_ADDR and NEXTSQL_CA are required\n");
    exit(1);
}

$conn = Client::connect([
    'address' => $addr,
    'database' => 'production',
    'user' => getenv('NEXTSQL_DATABASE_USER') ?: 'app',
    'password' => getenv('NEXTSQL_DATABASE_PASS') ?: 's3cret',
    'tls' => [
        'cafile' => $ca,
        'servername' => 'localhost',
    ],
]);

try {
    $conn->exec('CREATE TABLE items (
        id UUID PRIMARY KEY DEFAULT UUID(),
        sku STRING NOT NULL,
        qty DECIMAL(10,0)
    )');
    $ins = $conn->exec("INSERT INTO items (sku, qty) VALUES ('A-1', 3), ('B-2', 9)");
    if ($ins['affected'] !== 2) {
        throw new RuntimeException('inserted ' . $ins['affected']);
    }
    $sel = $conn->exec('SELECT sku, qty FROM items WHERE sku = $1', ['B-2']);
    if (count($sel['rows']) !== 1 || $sel['rows'][0][0] !== 'B-2') {
        throw new RuntimeException('select mismatch');
    }
    $st = $conn->prepare('SELECT sku FROM items WHERE sku = $1');
    $pres = $st->exec(['A-1']);
    if (count($pres['rows']) !== 1 || $pres['rows'][0][0] !== 'A-1') {
        throw new RuntimeException('prepared mismatch');
    }
    $st->close();
    $n = 0;
    foreach ($conn->query('SELECT sku FROM items') as $row) {
        if ($row[0] === '') {
            throw new RuntimeException('empty row');
        }
        $n++;
    }
    if ($n !== 2) {
        throw new RuntimeException('streamed ' . $n);
    }
    // Follower-read control frames round-trip against a standalone server.
    $status = $conn->nodeStatus();
    if ($status['role'] !== 'standalone' || $status['healthy'] !== true) {
        throw new RuntimeException('node status ' . json_encode($status));
    }
    $conn->setReadConsistency(Client::READ_BOUNDED, 5000);
    $bounded = $conn->exec('SELECT sku FROM items WHERE sku = $1', ['A-1']);
    if (count($bounded['rows']) !== 1) {
        throw new RuntimeException('bounded read mismatch');
    }
    $conn->setReadConsistency(Client::READ_STRONG);
} finally {
    $conn->close();
}
