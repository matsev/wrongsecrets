# Public File Share Links — Design

## Context

WrongSecrets is adding a "share via public link" feature: a user uploads a file and gets back a URL that anyone can open to view/download it, similar to Google Docs' or Dropbox's "anyone with this link" sharing. This is a genuine end-user feature (not a new vulnerable-by-design challenge), built to be properly secured.

Today, WrongSecrets has no per-user "document" model and no database — the only existing per-user state is `ScoreCard`, an HTTP-session-scoped, in-memory, non-persistent bean (`InMemoryScoreCard`, wired via `@Scope("session")` in `WrongSecretsApplication.java`). There is no `@Entity`/JPA/datasource configuration anywhere in the app. This feature introduces its own self-contained persistence on local disk rather than reusing or extending `ScoreCard`.

## Requirements (from stakeholder discussion)

- Anyone with a share link can view/download the file — no login required to read.
- Only the HTTP session that uploaded a file can manage it (list, delete) — no accounts, session-scoped ownership, consistent with the rest of the app's session model.
- Files expire automatically via a configurable TTL; expired files and their links stop working.
- Upload limits: a per-file size cap only, no file-type restriction (see "Upload quotas" and "Accepted risk" below for the per-session quota and residual-risk documentation added after security review).
- Opening a share link shows a landing page (filename, size, expiry, download button) rather than streaming the file directly.
- Persistence is local temporary disk storage — no new database dependency.

## Architecture

A new, self-contained package `org.owasp.wrongsecrets.sharing`, independent of the challenges/`ScoreCard` machinery. Three collaborators:

- **`ShareStorageService`** — disk I/O: writes/reads/deletes a file + its metadata sidecar.
- **`ShareRegistry`** — in-memory index over the disk store, rebuilt at startup, with a scheduled TTL sweep.
- **Two controllers**, split by auth model: session-owned upload/management vs. public anonymous read.

## Data model

`SharedFile` (record):

| Field | Purpose |
|---|---|
| `internalId` | Server-generated UUID; used only for the on-disk directory name. Never exposed to clients. |
| `publicToken` | Separate high-entropy token (128-bit, `SecureRandom`, URL-safe base64, ~22 chars) used in the public link. Kept distinct from `internalId` so link enumeration never reveals disk paths. |
| `ownerSessionId` | The `HttpSession.getId()` of the uploader; used for management authorization. |
| `originalFilename` | As uploaded, sanitized before use in headers (see Security). |
| `contentType` | As uploaded (or sniffed if absent). |
| `sizeBytes` | For display and quota bookkeeping. |
| `uploadedAt` / `expiresAt` | `expiresAt` computed from the configured TTL at upload time. |

On-disk layout: `{storage-root}/{internalId}/file` and `{storage-root}/{internalId}/meta.json`. `storage-root` is configurable (`wrongsecrets.sharing.storage-dir`), defaulting to a subdirectory under the OS temp dir.

## Components

- **`ShareStorageService`**
  - `store(bytes, metadata) -> internalId`: creates the directory, writes `file` and `meta.json`.
  - `read(internalId) -> InputStream`: streams file bytes for download.
  - `delete(internalId)`: removes the directory recursively.
  - Holds a per-`internalId` `ReentrantReadWriteLock` (see Concurrency below), acquired around every `read`/`delete`.
- **`ShareRegistry`**
  - `ConcurrentHashMap<publicToken, SharedFile>` as the primary index, plus a secondary index keyed by `ownerSessionId` for the "list my shares" view, and a third keyed by `ownerSessionId` tracking cumulative uploaded bytes and file count for quota enforcement (see Upload quotas below).
  - `@PostConstruct` rebuild: scans `storage-root`, reads each `meta.json`, repopulates all indices — so shares (and their expiry) survive an app restart.
  - `@Scheduled` sweep (default every 5 minutes, configurable): iterates entries where `expiresAt` has passed, calling `ShareStorageService.delete(...)` for each inside a per-entry `try`/`catch` — a failure on one entry is logged (`WARN`, with `internalId` and the exception) and the sweep continues with the remaining entries rather than aborting. A failed deletion is retried on the next sweep; the registry entry (and thus the `404`-on-lookup behavior described under Error handling) is removed from the index immediately regardless of whether the on-disk delete succeeds, so an expired file is never servable even if its bytes are still being cleaned up.
- **`ShareUploadController`** (session-scoped; mirrors how `ScoreCard` is wired per-session today)
  - `POST /shares` — multipart upload. Validates per-file size via `spring.servlet.multipart.max-file-size`, then checks the session's cumulative quota (see Upload quotas below) before accepting. Generates `internalId`/`publicToken`, stores, registers, returns the share URL.
  - `GET /shares` — lists the current session's own uploads (filename, size, expiry, delete action).
  - `DELETE /shares/{token}` — deletes only if `ownerSessionId` matches the current session; otherwise `404`.
- **`SharePublicController`** (no auth)
  - `GET /share/{token}` — landing page: filename, size, expiry, download button. `404` if missing or expired.
  - `GET /share/{token}/download` — streams the file with `Content-Disposition: attachment; filename="..."` (sanitized), `Content-Type: application/octet-stream` (always — see Security), and `X-Content-Type-Options: nosniff`.

## Storage-root validation

Since `storage-root` is configurable, a misconfigured or tampered path (e.g. pointed at a symlink) could let file writes escape the intended directory. `ShareStorageService` validates the storage root:

- **At startup** (`@PostConstruct`, before `ShareRegistry`'s own startup scan): resolve `storage-root` to an absolute path, reject if it is not absolute, reject if `Files.isSymbolicLink(storageRoot)` on the root or any parent component, and fail application startup (throw, don't degrade silently) if validation fails.
- **Before every write**: resolve `{storage-root}/{internalId}` via `Path.toRealPath()` and verify the result still starts with the canonicalized `storage-root` — this catches a symlink introduced after startup (TOCTOU) as well as any future bug that lets `internalId` escape its intended shape.
- **Atomic create**: files are written with `Files.newOutputStream(targetFile, StandardOpenOption.CREATE_NEW)`, which fails if the target already exists (including as a pre-planted symlink) rather than silently following/overwriting it.

## Upload quotas

Anonymous, no-login uploads mean a single visitor could otherwise exhaust disk space by opening many sessions or uploading many/large files. `ShareRegistry`'s per-`ownerSessionId` index tracks cumulative `sizeBytes` and file count for the session, in addition to the existing per-file size cap:

- Configurable per-session limits (e.g. `wrongsecrets.sharing.session-quota-bytes`, `wrongsecrets.sharing.session-quota-files`), checked by `ShareUploadController` before calling `ShareStorageService.store`.
- Exceeding either limit rejects the upload with `413` (reusing the same generic `ProblemDetail` pattern as the existing per-file size cap — no distinction in the response between "this file is too big" and "your session quota is used up," to avoid leaking quota internals).
- Quota state lives in the same session-keyed index as "list my shares," so it is naturally reset when a session ends (matching `ScoreCard`'s existing lifecycle) and isolated between sessions.

## Concurrency

A delete racing an in-flight download (either a manual `DELETE` or the TTL sweep) could otherwise produce a partial/corrupted read. `ShareStorageService` holds a `ConcurrentHashMap<internalId, ReentrantReadWriteLock>`:

- `read(internalId)` acquires the **read** lock for the full duration of the streaming response.
- `delete(internalId)` acquires the **write** lock before removing the directory, so it waits for in-flight downloads to finish (multiple concurrent downloads can proceed together under the shared read lock; a delete is exclusive with all of them).
- The registry entry is removed *before* the physical delete is attempted (see the sweep description above), so new download/landing-page requests get `404` immediately even while an old, already-in-flight download is still finishing under its read lock.

## Data flow

1. **Upload:** browser `POST /shares` (multipart) → controller validates size → `ShareStorageService.store` → `ShareRegistry` registers under both indices → returns `/share/{token}` to the uploader.
2. **Read:** anonymous `GET /share/{token}` → registry lookup by token → `404` if absent/expired → render landing page. `GET /share/{token}/download` → same lookup → `ShareStorageService.read(internalId)` streamed to the response.
3. **Manage:** session `GET /shares` → registry lookup by `ownerSessionId` → render list. `DELETE /shares/{token}` → ownership check → storage delete + registry removal.
4. **Expiry sweep:** scheduled task iterates the registry, removes anything past `expiresAt` from the index immediately and attempts the on-disk delete, retrying on failure (see Components above).

## Error handling

- Unknown or expired token → `404` for both the landing page and download endpoint. The two cases are never distinguished in the response, to avoid confirming to a prober whether a token ever existed.
- Delete attempted by a non-owner session → `404` (not `403`), same anti-enumeration rationale.
- Oversized upload → `413`, generic `ProblemDetail` response — reusing the pattern established in `ApiExceptionAdvice` (no raw exception messages in the body; the real cause is logged server-side only).
- Disk write failure (full disk, permission error) → `500`, generic detail message; full exception logged server-side via the existing `ApiExceptionAdvice.handleGenericException` path.

## Security considerations

- **Unguessable tokens:** `publicToken` generated via `SecureRandom`, never sequential/derived from `internalId` or upload order.
- **Path safety:** the on-disk path is always `{storage-root}/{internalId}/...` — `internalId` is server-generated, never derived from user input (filename, token), eliminating path traversal. See Storage-root validation above for symlink/TOCTOU handling on top of this.
- **Header injection:** `originalFilename` is sanitized (strip CR/LF and quote characters) before being placed into `Content-Disposition`.
- **No execution risk / no content-type reflection:** the download response always sets `Content-Disposition: attachment` (never rendered inline) *and* always sets `Content-Type: application/octet-stream`, regardless of what the uploader claimed or what the bytes look like — the originally-uploaded `contentType` is stored in metadata for display purposes only (e.g. shown on the landing page) and is never reflected into a response header. This closes the gap where a client-supplied `Content-Type` (e.g. `text/html`) could otherwise be reflected verbatim. `X-Content-Type-Options: nosniff` is set as well, as defense-in-depth against older browsers' content-sniffing.
- **Anti-enumeration:** uniform `404` for missing/expired/not-owned, as above.
- **Disk quota / DoS:** see Upload quotas above — per-session limits on top of the per-file size cap.
- **Concurrent access:** see Concurrency above — per-`internalId` locking prevents delete/download races.

### Accepted risk: no file-type restriction or content scanning

Per the stakeholder discussion (see Requirements above), uploads accept any file type with only a size cap — no extension allowlist, MIME-type validation, or malware/AV scanning. This is a deliberate scope decision, not an oversight, made to keep the feature general-purpose like Dropbox/Google Drive. The residual risk is that the app could be used to host and distribute malware or phishing content via a public link. The primary compensating control is that files are always served as an `application/octet-stream` attachment (never inline-rendered, never trusted by content-type — see above), which prevents the app itself from executing or rendering uploaded content, but does **not** prevent a downloader from choosing to run something they fetched.

**Accepted by:** project maintainer (design review, 2026-08-30). Revisit if this feature sees real public traffic — the natural follow-up would be integrating a malware scan (e.g. ClamAV) before a file becomes downloadable, without changing the "any file type" policy.

## Testing

- **Unit tests** — `ShareStorageService`: store/read/delete round-trip; sidecar `meta.json` round-trips all fields; storage-root validation rejects a non-absolute path and a symlinked root at startup; a write to a target that already exists (e.g. a pre-planted symlink) fails via `CREATE_NEW` rather than following it. `ShareRegistry`: TTL sweep removes only expired entries; a simulated deletion failure for one entry is logged and does not prevent the sweep from processing the rest, and the failed entry is retried on the next sweep; startup rebuild from an on-disk fixture restores all indices (including per-session quota totals) correctly.
- **Concurrency tests** — a `delete(internalId)` invoked while a `read(internalId)` is in progress blocks until the read completes (or the read completes cleanly and the delete proceeds after); no partial/corrupted stream is ever observed.
- **`MockMvc` tests** — `ShareUploadControllerTest`: upload returns a working link; a session exceeding its configured byte/file quota gets `413` on the next upload; `GET /shares` lists only the caller's own uploads; `DELETE` from a different session ID returns `404` and leaves the file intact. `SharePublicControllerTest`: valid token renders the landing page and downloads with `Content-Disposition: attachment`, `Content-Type: application/octet-stream`, and `X-Content-Type-Options: nosniff` regardless of the uploaded content-type (e.g. uploading a `text/html` file still downloads as `application/octet-stream`, never rendered); expired/unknown token returns `404` from both endpoints; oversized upload returns `413`; a filename containing CR/LF/quote characters does not produce a split or injected header.

## Out of scope (for this design)

- User accounts / cross-session ownership transfer.
- File-type restrictions or content scanning (see "Accepted risk" above).
- Per-file access controls beyond "anyone with the link" (e.g. link passwords, view limits) — noted as a possible future extension, not built now.

## Oplane security review

This design was reviewed with Oplane (threat model `3e36c675-69d8-4f65-b142-b282dc481ad6`, tied to PR #4) before implementation began. Of 9 requirements raised, 2 were already satisfied by the original spec (filename sanitization, uniform 404s), 1 was an accepted risk (unrestricted file types, now documented above with sign-off), and 6 gaps were identified and are now incorporated into this revision: storage-root path/symlink/TOCTOU validation, per-session upload quotas, per-`internalId` concurrency locking, forcing `Content-Type: application/octet-stream` + `nosniff` instead of reflecting the uploaded content-type, and robust per-entry error handling in the TTL sweep.
