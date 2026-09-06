# bzync/nextsql

Official [NextSQL](https://nextsql.bzync.com) driver for PHP 8.1+. Speaks the native
NSQL v1 wire protocol over TLS 1.3. No Composer dependencies (needs `ext-openssl`).

Encryption keys and passwords are **never** accepted in a connection URL.

```bash
composer require bzync/nextsql
```

```php
<?php
require 'vendor/autoload.php';

$conn = NextSQL\Client::connect([
    'address'  => 'db.example.com:7210',
    'database' => 'production',
    'user'     => 'app',
    'password' => getenv('NEXTSQL_DATABASE_PASS'),
    'tls'      => ['cafile' => '/etc/nextsql/ca.pem', 'servername' => 'db.example.com'],
]);

$res = $conn->exec('SELECT id, name FROM users WHERE id = $1', [1]);
foreach ($res['rows'] as $row) {
    print_r($row);
}
$conn->close();
```

Plaintext connections are allowed only on loopback (`'insecureNoTLS' => true`).
For an HA cluster with follower-read routing, use `NextSQL\Cluster::connect`.

- Full driver docs: <https://nextsql.bzync.com/docs/drivers>
- Wire protocol: <https://github.com/bzync/nextsql/blob/master/docs/protocol.md>

MIT licensed.
