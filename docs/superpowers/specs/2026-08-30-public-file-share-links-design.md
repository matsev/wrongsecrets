# Public File Share Links — Design

## Context

WrongSecrets is adding a "share via public link" feature: a user uploads a file and gets back a URL that anyone can open to view/download it, similar to Google Docs' or Dropbox's "anyone with this link" sharing. This is a genuine end-user feature (not a new vulnerable-by-design challenge), built to be properly secured.

Today, WrongSecrets has no per-user "document" model and no database — the only existing per-user state is `ScoreCard`, an HTTP-session-scoped, in-memory, non-persistent bean (`InMemoryScoreCard`, wired via `@Scope("session")` in `WrongSecretsApplication.java`). There is no `@Entity`/JPA/datasource configuration anywhere in the app. This feature introduces its own self-contained persistence on local disk rather than reusing or extending `ScoreCard`.

## Requirements (from stakeholder discussion)

- Anyone with a share link can view/download the file — no login required to read.
- Only the HTTP session that uploaded a file can manage it (list, delete) — no accounts, session-scoped ownership, consistent with the rest of the app's session model.
- Files expire automatically via a configurable TTL; expired files and their links stop working.
- Upload limits: a size cap only, no file-type restriction.
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
- **`ShareRegistry`**
  - `ConcurrentHashMap<publicToken, SharedFile>` as the primary index, plus a secondary index keyed by `ownerSessionId` for the "list my shares" view.
  - `@PostConstruct` rebuild: scans `storage-root`, reads each `meta.json`, repopulates both indices — so shares (and their expiry) survive an app restart.
  - `@Scheduled` sweep (default every 5 minutes, configurable): removes entries where `expiresAt` has passed, calling `ShareStorageService.delete(...)` for each.
- **`ShareUploadController`** (session-scoped; mirrors how `ScoreCard` is wired per-session today)
  - `POST /shares` — multipart upload. Validates size via `spring.servlet.multipart.max-file-size`. Generates `internalId`/`publicToken`, stores, registers, returns the share URL.
  - `GET /shares` — lists the current session's own uploads (filename, size, expiry, delete action).
  - `DELETE /shares/{token}` — deletes only if `ownerSessionId` matches the current session; otherwise `404`.
- **`SharePublicController`** (no auth)
  - `GET /share/{token}` — landing page: filename, size, expiry, download button. `404` if missing or expired.
  - `GET /share/{token}/download` — streams the file with `Content-Disposition: attachment; filename="..."` (sanitized) and the stored `Content-Type`.

## Data flow

1. **Upload:** browser `POST /shares` (multipart) → controller validates size → `ShareStorageService.store` → `ShareRegistry` registers under both indices → returns `/share/{token}` to the uploader.
2. **Read:** anonymous `GET /share/{token}` → registry lookup by token → `404` if absent/expired → render landing page. `GET /share/{token}/download` → same lookup → `ShareStorageService.read(internalId)` streamed to the response.
3. **Manage:** session `GET /shares` → registry lookup by `ownerSessionId` → render list. `DELETE /shares/{token}` → ownership check → storage delete + registry removal.
4. **Expiry sweep:** scheduled task iterates the registry, removes anything past `expiresAt` (storage + both indices).

## Error handling

- Unknown or expired token → `404` for both the landing page and download endpoint. The two cases are never distinguished in the response, to avoid confirming to a prober whether a token ever existed.
- Delete attempted by a non-owner session → `404` (not `403`), same anti-enumeration rationale.
- Oversized upload → `413`, generic `ProblemDetail` response — reusing the pattern established in `ApiExceptionAdvice` (no raw exception messages in the body; the real cause is logged server-side only).
- Disk write failure (full disk, permission error) → `500`, generic detail message; full exception logged server-side via the existing `ApiExceptionAdvice.handleGenericException` path.

## Security considerations

- **Unguessable tokens:** `publicToken` generated via `SecureRandom`, never sequential/derived from `internalId` or upload order.
- **Path safety:** the on-disk path is always `{storage-root}/{internalId}/...` — `internalId` is server-generated, never derived from user input (filename, token), eliminating path traversal.
- **Header injection:** `originalFilename` is sanitized (strip CR/LF and quote characters) before being placed into `Content-Disposition`.
- **No execution risk:** files are always served as `attachment`, never rendered inline, regardless of content type — no file-type restriction was requested, so this is the compensating control instead.
- **Anti-enumeration:** uniform `404` for missing/expired/not-owned, as above.

## Testing

- **Unit tests** — `ShareStorageService`: store/read/delete round-trip; sidecar `meta.json` round-trips all fields. `ShareRegistry`: TTL sweep removes only expired entries; startup rebuild from an on-disk fixture restores both indices correctly.
- **`MockMvc` tests** — `ShareUploadControllerTest`: upload returns a working link; `GET /shares` lists only the caller's own uploads; `DELETE` from a different session ID returns `404` and leaves the file intact. `SharePublicControllerTest`: valid token renders the landing page and downloads with correct headers; expired/unknown token returns `404` from both endpoints; oversized upload returns `413`.

## Out of scope (for this design)

- User accounts / cross-session ownership transfer.
- File-type restrictions or content scanning.
- Per-file access controls beyond "anyone with the link" (e.g. link passwords, view limits) — noted as a possible future extension, not built now.
