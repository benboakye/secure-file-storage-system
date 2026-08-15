# Storage-capacity reservations

## Purpose

Capacity reservations prevent concurrent API processes from independently approving uploads that collectively exceed an account quota or the configured protected-storage pool. They are admission control, not billing records and not a replacement for filesystem monitoring.

The enforced pool defaults to 50 GiB with a 5 GiB safety reserve. Deployment may set `SECURESTORE_STORAGE_CAPACITY_BYTES` and `SECURESTORE_STORAGE_RESERVE_BYTES`, but the configured pool must not exceed the dedicated storage volume actually provisioned for SecureStore. The existing capacity dashboard continues to report the hosting volume independently because that volume can contain unrelated data.

## Admission sequence

1. The browser sends the exact `File.size` value in `X-File-Size`. Empty or oversized declarations are rejected before file processing.
2. The API creates the upload's idempotent metadata row, then requests a capacity reservation for that upload.
3. PostgreSQL acquires a transaction-scoped global advisory lock and an owner-scoped advisory lock, removes expired reservations, and calculates authoritative charged usage plus active reservations.
4. The transaction rejects the request if either the owner's quota or the usable global pool (`capacity - safety reserve`) would be exceeded. Otherwise it inserts one reservation keyed by upload ID.
5. Streaming enforces the declaration as an exact byte contract. A longer or shorter body fails, removes partial quarantine data and metadata, and releases the reservation.
6. The reservation remains while the file is quarantined, inspected, and encrypted. It is released only after `stored`, `rejected`, or `failed` metadata is durable. At that point the durable upload size replaces the reservation in usage accounting.

Rows expire after one hour by default. Expiry prevents abandoned requests from reserving capacity forever. A crash after a terminal metadata commit but before release remains fail safe: the reservation temporarily represents the same upload instead of double-counting it, and later expiry returns accounting to the durable upload row.

## Restart and failure behavior

The initial upload row exists before request bytes are streamed because the reservation references it. A process crash in this interval leaves a zero-byte quarantined row. Startup treats that state as `upload_reception_incomplete`, removes any partial quarantine object, marks the upload failed, and releases its reservation. Partial request bodies are never sent to malware inspection.

Transient database failures deny admission before any quarantine file is created. Reservation cleanup is idempotent, and deleting an upload row cascades to its reservation. PostgreSQL is the cross-process authority; the memory repository implements the same semantics for development tests but cannot claim restart durability.

## Operational signals

The Resource metadata dashboard reports the enforced pool, safety reserve, active reservation count, and reserved bytes. System monitoring reports the same policy and reservation lifetime. These values are safe aggregate metadata and expose neither filesystem paths nor object names.

Backups remain explicitly deferred to deployment hardening and are not included in capacity-reservation accounting.
