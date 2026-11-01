-- Revision 1 has not shipped. After shipment this file is immutable.
-- Q-control: directly readable, bounded bootstrap values with their own checksum.
CREATE TABLE control (
 name TEXT NOT NULL CHECK(length(CAST(name AS BLOB))<=4096),
 value_version INTEGER NOT NULL CHECK(value_version BETWEEN 1 AND 4294967295),
 value BLOB NOT NULL CHECK(length(value)<=16384),
 row_checksum BLOB NOT NULL CHECK(length(row_checksum)=16),
 PRIMARY KEY(name)
) STRICT, WITHOUT ROWID;
-- Q-record/Q-kind/Q-family. All key bytes are exact; position is monotonic.
CREATE TABLE records (
 kind TEXT NOT NULL CHECK(length(kind) BETWEEN 1 AND 255),
 key_bytes BLOB NOT NULL CHECK(length(key_bytes)<=4096),
 position INTEGER NOT NULL CHECK(position>=0),
 value_version INTEGER NOT NULL CHECK(value_version BETWEEN 1 AND 4294967295),
 header BLOB CHECK(header IS NULL OR length(header)<=512),
 value_digest BLOB NOT NULL CHECK(length(value_digest)=16),
 row_checksum BLOB NOT NULL CHECK(length(row_checksum)=16),
 value_bytes INTEGER NOT NULL CHECK(value_bytes BETWEEN 0 AND 67108864),
 chunk_count INTEGER NOT NULL CHECK(chunk_count BETWEEN 0 AND 256),
 inline_value BLOB,
 CHECK((chunk_count=0 AND value_bytes<=512 AND inline_value IS NOT NULL AND length(inline_value)=value_bytes)
    OR (chunk_count>0 AND value_bytes>512 AND inline_value IS NULL AND chunk_count=(value_bytes+262143)/262144)),
 PRIMARY KEY(kind,key_bytes,position)
) STRICT, WITHOUT ROWID;
-- Q-shared and Q-reuse. Hash collisions coexist; reuse compares full evidence.
CREATE TABLE shared_values (
 class TEXT NOT NULL CHECK(class='request_hash_set'),
 id INTEGER NOT NULL CHECK(id>0),
 lookup_hash BLOB NOT NULL CHECK(length(lookup_hash)=32),
 ref_count INTEGER NOT NULL CHECK(ref_count>0),
 value_version INTEGER NOT NULL CHECK(value_version BETWEEN 1 AND 4294967295),
 value_digest BLOB NOT NULL CHECK(length(value_digest)=16),
 row_checksum BLOB NOT NULL CHECK(length(row_checksum)=16),
 value_bytes INTEGER NOT NULL CHECK(value_bytes BETWEEN 0 AND 67108864),
 chunk_count INTEGER NOT NULL CHECK(chunk_count BETWEEN 0 AND 256),
 inline_value BLOB,
 CHECK((chunk_count=0 AND value_bytes<=512 AND inline_value IS NOT NULL AND length(inline_value)=value_bytes)
    OR (chunk_count>0 AND value_bytes>512 AND inline_value IS NULL AND chunk_count=(value_bytes+262143)/262144)),
 PRIMARY KEY(class,id)
) STRICT, WITHOUT ROWID;
CREATE INDEX shared_values_lookup ON shared_values(class,lookup_hash);
-- Q-chunks: disjoint table namespace and complete parent primary key.
CREATE TABLE value_chunks (
 owner_table TEXT NOT NULL CHECK(owner_table IN ('records','shared_values')),
 owner_kind TEXT NOT NULL CHECK(length(owner_kind) BETWEEN 1 AND 255),
 owner_key BLOB NOT NULL CHECK(length(owner_key)<=4096),
 position INTEGER NOT NULL CHECK(position>=0),
 chunk_no INTEGER NOT NULL CHECK(chunk_no BETWEEN 0 AND 255),
 chunk BLOB NOT NULL CHECK(length(chunk) BETWEEN 1 AND 262144),
 PRIMARY KEY(owner_table,owner_kind,owner_key,position,chunk_no)
) STRICT, WITHOUT ROWID;
