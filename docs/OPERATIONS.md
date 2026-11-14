# Operations

Backup, restore and what vaultd's startup refusals mean. `$DATA` is the data directory (`VAULT_DATA_DIR`; the `vault-data` volume, mounted at `/data`, under Compose).

## What to back up

One instance is four things. They belong together and are restored together.

| Item | Holds | If lost |
|---|---|---|
| `$DATA/vault.db` | Every file's record, the accounts, the sessions, the audit log | All shares and accounts. vaultd refuses to create a new one over stored content |
| `$DATA/account.key` | The server key for accounts | Authenticator codes stop working and every browser must sign in again. vaultd refuses to create a new one beside existing accounts |
| `$DATA/audit.key` | The key that hashes client addresses in the audit log | Created anew without notice. Address hashes written before and after no longer compare |
| `$DATA/blobs/`, or the S3 bucket | The encrypted files | The shares they belong to |

While vaultd runs, `vault.db-wal` and `vault.db-shm` sit next to the database. They are part of it: never copy `vault.db` alone from a running instance.

A backup deserves the protection of the server itself. It holds the auth key of every share, which passes the download check, the Argon2id hashes of the accounts' sign-in secrets, and `account.key`, which opens the stored two-factor secrets. It holds nothing that decrypts a file.

## Backup with vaultd stopped

The simplest backup that is certain to be consistent.

```bash
# stop vaultd, then:
umask 077    # the archive holds the keys
tar -czf vault-backup.tar.gz -C "$DATA" .
# start vaultd
```

Under Compose, where the vaultd image has no shell:

```bash
docker compose stop vaultd
docker run --rm --volumes-from "$(docker compose ps -aq vaultd)" -v "$PWD:/backup" \
  busybox:1.36 sh -c 'umask 077 && tar -czf /backup/vault-backup.tar.gz -C /data .'
docker compose start vaultd
```

With S3 storage the archive holds no files. Copy the bucket with the provider's tools after the archive is made.

## Backup while vaultd runs

Copy the database first, then the keys, then the content. In this order every record in the copied database finds its content, except for files that were burned or deleted in between, which is what would have happened to them anyway.

```bash
umask 077    # VACUUM INTO creates its copy with the default mode
mkdir -p "$BACKUP"
sqlite3 "$DATA/vault.db" "VACUUM INTO '$BACKUP/vault.db'"
cp -p "$DATA/account.key" "$DATA/audit.key" "$BACKUP/"
cp -a "$DATA/blobs" "$BACKUP/"    # or copy the bucket
```

`VACUUM INTO` writes a consistent copy of a database in use; a plain `cp` of `vault.db` does not. The target must not exist yet. `sqlite3` needs write access to `$DATA`. `blobs/tmp` holds uploads in flight; vaultd removes what is left there after a restore.

## Restore

Restore into an empty data directory, with vaultd stopped, and restore all four items from the same backup.

```bash
# stop vaultd, empty $DATA, then one of:
tar -xzf vault-backup.tar.gz -C "$DATA"    # a stopped backup
cp -a "$BACKUP/." "$DATA/"                 # a running backup
# start vaultd
```

Under Compose:

```bash
docker compose stop vaultd    # on a new host: docker compose create vaultd
docker run --rm --volumes-from "$(docker compose ps -aq vaultd)" -v "$PWD:/backup:ro" \
  busybox:1.36 sh -c 'find /data -mindepth 1 -delete && tar -xzf /backup/vault-backup.tar.gz -C /data'
docker compose start vaultd
```

The files must stay readable only by the user vaultd runs as (uid 65532 in the image); `tar` and `cp -a` run as root keep owner and mode. Then check `https://<host>/healthz` and the log.

A restore takes the instance back to the moment of the backup:

- A file that was burned or deleted since, and has not expired, is served again if its content is still in the storage. Download counts go back to their old values. If this matters, restore the content from the same backup as the database instead of keeping the newer storage.
- A file uploaded since the backup has no record. Its content is deleted as leftover from an hour after the start, at most 100 objects an hour, and each sweep that finds more logs a warning.
- A record whose content is missing fails on download and goes when it expires.
- Sessions and accounts are those of the backup.

## Startup refusals

vaultd checks two things before it serves anything and exits with a message when one fails. Neither has an override setting.

**`vault.db is missing or empty, but the storage already holds content`.** A new database would have no record of the stored files, and cleanup would delete them. Either the database was lost or left out of a restore: restore it. Or the storage belongs to another instance, or the old content is not wanted: point vaultd at the right place, or empty `blobs/` or the bucket and start over.

**`account.key does not exist, but the database already holds accounts`.** The key was lost or left out of a restore: restore it from the same backup as the database. If it is gone for good, create a new one on purpose:

```bash
# as the user vaultd runs as
(umask 077 && head -c 32 /dev/urandom > "$DATA/account.key")
```

Under Compose, where that user is uid 65532:

```bash
docker run --rm --volumes-from "$(docker compose ps -aq vaultd)" busybox:1.36 \
  sh -c 'umask 077 && head -c 32 /dev/urandom > /data/account.key && chown 65532:65532 /data/account.key'
```

With a new key:

- An account with two-factor sign-in can no longer use its authenticator: a code from the app gets a server error. A recovery code still signs in; the user then turns two-factor sign-in off and on again.
- Every browser must sign in again, and is treated as one the account has not seen before.
- The made-up salts that hide which usernames exist change, while those of real accounts stay. Someone who asked for salts before the change can ask again and tell the two apart.
- Passwords, files and "My files" are not affected.

Without accounts in the database, a missing `account.key` is created as on a first start.

## Account cap

When sign-up answers 503 `capacity`, the instance holds `VAULT_MAX_ACCOUNTS` accounts (10,000 by default). Raise `VAULT_MAX_ACCOUNTS` and restart vaultd. Accounts never expire, and vaultd provides no way to delete an account other than its owner's own deletion.

## Health check

`GET /healthz` answers 200 when the database answers a query, the storage takes a write (on S3: the bucket answers) and the data volume has at least 128 MiB free; otherwise 503, with the reason in the log. Results are reused for 5 seconds.

- 128 MiB is a fixed floor under which the database and small uploads soon fail. It says nothing about room for a large upload; size the quota (`VAULT_MAX_TOTAL_BYTES`) to the disk.
- The check reads one row. It does not find damaged pages elsewhere in the database, and vaultd runs no integrity check at startup. `sqlite3 vault.db "PRAGMA integrity_check"` on a backup does.
- Compose defines no health check for the vaultd container; probe `/healthz` from outside.
