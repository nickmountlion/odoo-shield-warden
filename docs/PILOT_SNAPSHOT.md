# Fraud Exposure Snapshot: consent and data handling (draft for a lawyer to review)

**Status: waiting on a real client.** Nothing here has been run on a client's data. All "money at risk" figures in our
material come from our own lab. This note and `tools/pilot_snapshot.py` are the preparation.

## What it is
One Shield assessment on 12 months of a client's data, and a 30-minute readout: how much money touched risky events,
which users hold toxic rights, which bank-account changes preceded a payment.

## What gets read
Vendor bank accounts and their change history, outbound payments, vendor bills, users and their access rights, and
chatter messages about bank changes. It does **not** need invoice line detail, customer data, payroll or documents.
Be honest with the client: the assessment does read names and bank account numbers of vendors.

## Where it runs
Never on production. The client (or its Odoo partner) restores a backup into an isolated Odoo that is not reachable from
the internet and installs the Shield modules there. Running the assessment writes records into that copy, which is why it
must be a copy. `tools/pilot_snapshot.py` refuses a non-local URL unless `--copy-confirmed` is passed.

## Who sees what
Only what appears in the readout and `snapshot-<db>/` (summary + scorecard). We do not need the database file. If the
client prefers, the partner runs it and shares only the scorecard.

## When it is deleted
The restored copy and the `snapshot-<db>/` folder are deleted at the end of the readout, or within 7 days at the latest
[proposal]. The client receives the scorecard and decides what to keep. No vendor bank numbers are kept by us.

## Consent checklist (client signs before any data is restored)
- [ ] Named person at the client with the authority to consent.
- [ ] Scope above understood, including that vendor names and bank numbers are read.
- [ ] Where the copy lives and who has access.
- [ ] Deletion date.
- [ ] Argentine data-protection rules (Ley 25.326) checked by a lawyer: **not done**.

## Run (after consent)
```
python tools/pilot_snapshot.py --db client_copy --url http://localhost:8069 --login admin --password <password>
```
