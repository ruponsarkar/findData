# findData

A local finance workspace for finding bank statement charges in PDF, Excel (`.xlsx`, `.xls`), and UTF-8 CSV files. FastAPI serves the responsive UI; SQLite stores documents, extracted rows, editable phrases, matches, and review status. Uploaded originals live on disk.

## Run

Python 3.11+ recommended.

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# Or use requirements.lock.txt for the exact tested dependency versions.
uvicorn app:app --host 127.0.0.1 --port 8008
```

Open http://127.0.0.1:8008. Use **Load sample statement** to try a clearly labeled sample, or upload your own files. API documentation: http://127.0.0.1:8008/docs.

## Run with PM2

From the project directory, with the virtual environment and dependencies installed:

```sh
npm install -g pm2
pm2 start ecosystem.config.js
pm2 save
```

Stop any manually running Uvicorn server with Ctrl+C first, so port 8008 is available. Open http://127.0.0.1:8008. The configuration uses `.venv/bin/python` directly, so activating the virtual environment is unnecessary. It runs one Uvicorn worker, restarts after crashes, and disables file watching to avoid restarts when uploads or database files change.

```sh
pm2 status
pm2 logs findData
pm2 restart findData   # After application code changes
pm2 stop findData
pm2 delete findData   # Remove from PM2; does not delete application data
```

For automatic startup after reboot, run `pm2 startup`, execute the setup command PM2 prints, then run `pm2 save` again. PM2 detects the startup system (launchd on macOS). If you deliberately remove an application, run `pm2 save` afterward to update the saved process list. See [PM2 startup documentation](https://doc.pm2.io/en/runtime/guide/startup-hook/).

After editing the process configuration, apply it with `pm2 restart ecosystem.config.js --update-env`. PM2 keeps its logs under `~/.pm2/logs`; configure log rotation for long-running installations. The default binding remains localhost; see the HTTPS deployment notes below for access from other machines.

## What it does

- Upload multiple files, up to 250 MB per file by default; two background processing workers, chunked uploads and batched database writes.
- Edit, enable, disable or delete case-insensitive search phrases. Changes rescan stored rows. Matches use whole phrase boundaries and normalize whitespace.
- Review full matching spreadsheet rows with sheet name, actual row number and cell range. Repeated headers are recognized; metadata rows are preserved.
- Extract PDF text with page and row bounding box coordinates in PDF points. Recognized ruled tables retain columns; other pages use geometrically grouped text rows. Open the original PDF from each match.
- Identify debits from explicit debit/withdrawal columns, preserve signed amount columns, and show totals separately by currency. Unknown currency stays unknown and is excluded from totals (a dollar sign alone is ambiguous). Rows matching several phrases count once in totals.
- Matches default to **Awaiting review**. Select individual rows or **Select all visible matches**, then **Mark selected as reviewed** to clear them from that view without deleting them. Choose **Reviewed** or **All review states** to see them again.
- Use **Manage keywords** above the results or **Search keywords** in the sidebar to add, edit, disable or remove search phrases.
- Track reviewed matches, filter results and export matching records with full row data as CSV. CSV exports neutralize spreadsheet formula prefixes.
- Delete a statement and its original file, extracted rows and matches; retry failed processing. Queued or interrupted jobs resume at startup.

## Data and limitations

Everything is stored in `data/ledger.sqlite3` and `data/uploads/`, ignored by Git. Back up both together while the application is stopped. Set `LEDGER_DATA_DIR` to change storage and `MAX_UPLOAD_MB` to change the limit. Run **one server process**; processing jobs are in-process and recover on restart.

## Accounts and remembered sign-in

On first launch, create your account. **The first account inherits the existing local statements, keywords and review history.** Create this account before sharing the server. Later users choose **Create an account** on the sign-in page and receive their own private workspace with default keywords. Registration is open to anyone who can reach the installation; there is no invitation or administrator approval flow.

Accounts persist in SQLite. Login passwords use salted scrypt hashes; raw login passwords are never saved. Each browser stays signed in for 30 days through an HttpOnly, SameSite cookie. Only a hash of its random session token is stored in SQLite. Sessions survive server restarts, expire automatically and are revoked by **Log out**. Clearing browser cookies or using a different browser requires signing in again. File passwords remain separately encrypted. Password recovery and account administration are not yet included.

Every document, match, review and keyword is scoped to its account, including downloads, PDF previews, exports and background processing. Existing database tables migrate automatically at startup.

The default server is still bound to localhost. For other machines to connect, deploy behind an HTTPS reverse proxy, set `COOKIE_SECURE=1`, and configure trusted proxy headers appropriately. Shared production deployment also needs operational backups and a durable worker queue. Do not send login credentials over public plain HTTP.

Scanned/image-only PDFs require external OCR and are explicitly flagged; OCR is not bundled. Password-protected PDFs and supported encrypted Excel files can be unlocked by pasting a password before upload, or via **Statements → Enter password**. Incorrect passwords can be retried without uploading again. Passwords are saved encrypted per file after successful processing and reused for retries and PDF previews. The local encryption key is `data/.password-key`; back it up together with the database. The key and database are on the same machine, so this is not protection against someone with full access to your data directory. Original files remain unchanged. Use **Forget password** in Statements to remove a saved password. Files processed before this feature need their password entered once using **Save password**. Excel decryption uses a temporary file that is removed after processing; older unsupported encryption formats may still need an unlocked copy. Arbitrary PDF layouts, wrapped descriptions and unusual headers require source verification. Phrase matching occurs within extracted rows, not across separate rows. Amounts from unrecognized PDF columns remain unknown rather than being guessed; only recognized debit/amount columns contribute to totals. Mixed scanned/text PDFs may yield partial results with warnings. Excel formulas use cached values; recalculate and save files before upload. PDF table detection is best effort. Large files process in the background, but the current dashboard loads all matches; very large result sets need server pagination for production scale.

## Tests

```sh
pip install pytest httpx
pytest -q
```

Tests cover spreadsheet full rows and locations, debit totals without keyword duplication, PDF page coordinates, phrase edits/rescanning, reviews, export filters, deletion and invalid files, encrypted PDF/Excel uploads, incorrect passwords and successful password retries. Authentication tests cover remembered sessions, logout/revocation, expiry, account isolation, cross-origin protection, login rate limiting, and legacy data migration.
