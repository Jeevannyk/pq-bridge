# NetBank: the customer web app of PQBank

A real internet-banking front end for the mini-bank. Customers sign in with a username and password, see their accounts, read statements, pay and transfer money, and manage payees and their profile. It runs on the bank's own services, so everything the migration engine changes (TLS, token signatures, audit signatures) sits underneath this app.

**Open it:** https://localhost:8443/ (the bank must be running). The gateway's certificate comes from the bank's own RSA root, which browsers do not know yet: choose *Advanced, Proceed to localhost*, or import `testbed/runtime/pki/rsa-root.crt` into your trust store.

| Customer | Password | Accounts |
|---|---|---|
| vamsh | `vamsh` | ACC-0004 Savings, ACC-0005 Current |
| rahul | `Rahul#Bank2026` | ACC-0006 Savings, ACC-0007 Current |
| meera | `Meera#Bank2026` | ACC-0008 Savings, ACC-0009 Current |

## What you can do

| Page | Features |
|---|---|
| Sign in | Username and password, lockout for a minute after 5 failures, silent token refresh, sign-out after 10 minutes idle |
| Overview | Total and per-account balances, recent activity across accounts, last sign-in |
| Statement | Per-account history with running balance, date and in/out filters, load more, CSV download, held and declined payments |
| Pay & transfer | Own accounts, saved payees or any account number; name check before paying; review step; one Idempotency-Key per reviewed payment so a retry can never pay twice; receipt with reference; limits shown |
| Payees | Add (verified by name enquiry), pay, remove |
| Profile | Edit email and mobile, change password (signs every session out), the signature algorithm of your current session |

## Where the code is

| Part | Location |
|---|---|
| Web app (HTML, CSS, JS, no build step) | `netbank/frontend/`, served by the gateway from `/netbank` |
| Sign-in, refresh, logout | `testbed/apps/identity.py` (`/api/auth/*`) |
| Statements, payees, name enquiry, profile, password | `testbed/apps/accounts.py` (`/api/accounts/*`) |
| Payments, receipts, limits | `testbed/apps/payments.py` (`/api/payments/*`) |
| Double-entry posting and audit log | `testbed/apps/ledger.py` (unchanged) |
| Tables, demo customers | `testbed/apps/dbinit.py` |

No new services: the app uses the existing gateway, identity, accounts, payments and ledger. The old OAuth endpoints stay, because the legacy app and the verification gate still use them.

## Notes

- Money is stored as integer paise. Paying yourself is allowed between your own accounts; the daily limit and the new-payee review rule still apply.
- Access tokens are JWTs signed through the KMS. After the *Token signer* migration the profile page shows `FN-DSA-512` and the session continues without a new sign-in.
- The gateway sets `Content-Security-Policy`, `X-Frame-Options` and `nosniff`. All user text is escaped before it is shown, and CSV export neutralises spreadsheet formulas.
- The public certificate stays RSA until customers' devices can verify FN-DSA, so this app also demonstrates why that migration task is deferred.
