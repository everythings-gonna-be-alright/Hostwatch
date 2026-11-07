# 0004 History compressed as it is written, append-only, crash-safe

**Context.** Plain JSONL history wrote ~24 MB a day uncompressed and compressing finished files rewrote them. A
crash must not lose or duplicate events, and Time Travel must read a time range without decompressing whole files.

**Decision.** `HistoryStream`: events are deflated into the open gzip member as they arrive; zlib's sync flush every
second pushes them to disk without closing the member; a member is finished every 30 s or 4 MB and gets a line in a
`.blocks` list (offset, length, time range, bytes per minute). When the file is full the `.blocks` list becomes
the final `.idx`. Nothing is rewritten, nothing written twice; after a crash the unfinished tail is inflated up to
the last whole line and sealed as one block.

**Consequences.** ~1/22 of the raw bytes reach the disk; a crash loses at most one second. Readers must handle a
streaming file whose block list is still empty. The cap counts compressed bytes. `zcat`/`zgrep` still work on the
files because each member is a valid gzip stream.
