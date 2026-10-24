# SIH Demonstration Walkthrough — IPsec Analyzer

A step-by-step script for demonstrating the platform. Everything below uses
offline/lab captures only; never demonstrate with unauthorized production traffic.

## Setup
- Full stack: `docker compose up --build` → open `http://localhost:8080`.
- Log in as the seeded **analyst** (demo) account; note the Org/Role badges
  and the green Backend *ready* indicator in the top bar.

## 1. Offline PCAP upload & integrity
1. Go to **Captures → Upload Capture** and drop a lab IKEv2 PCAP.
   - Point out: the browser inspects only the first 16 magic bytes
     (PCAP/PCAPNG, incl. nanosecond variants) before anything is sent.
2. After upload, show the **server-computed SHA-256** (authoritative) and the
   truncated hash with one-click copy in the table.
3. Open the capture and choose **Run Security Analysis**.

## 2. Encrypted-visibility honesty
1. Poll to completion, open **Protocol & Security Inspector**.
2. Show IKE SA offered vs responder-**selected** transforms (offered ≠ active).
3. Show the **Visibility Boundary** callout: Child SA cipher/PFS are
   *Unknown — Encrypted Gap*, never guessed, never green/"secure".

## 3. Lab Manifest ground-truth comparison
1. On the capture, attach a **Lab Manifest** (guided form). Mention secret keys
   (PSK/private keys) are rejected client- and server-side.
2. Re-run analysis; show Packet Observed vs Lab Manifest provenance badges
   side-by-side and any ⚠ **discrepancy** highlighting.

## 4. Probabilistic traffic inference
1. Open **AI Traffic Inference**: predicted category with *calibrated*
   confidence, the metadata-only methodological notice (no payload
   decryption), abstention when confidence is low, and the Outer Metadata
   Exposure card (endpoints/SPI/timing visible without decryption).

## 5. Threat matrix assessment
1. Open **Security Assessment & Threat Matrix**: risk + security scores always
   paired with Evidence Coverage; Protocol vs ML confidence kept separate.
2. Click a matrix domain (e.g. ESP Confidentiality) to filter findings;
   expand a finding for Actual vs Expected, linked evidence, remediation.
3. With an ESP-only capture, show **Score Withheld — Insufficient Evidence**.

## 6. Executive / Technical reporting
1. Open the **Report Center** (`/analyses/:id/report`).
2. Toggle **Executive** (posture, top risks, roadmap, limitations) and
   **Technical** (evidence table with frame refs, rule-by-rule actual vs
   expected, versions + UTC timestamps).
3. **Download PDF** and **JSON** — authenticated Blob downloads; tokens never
   appear in URLs.

## 7. Governance (admin)
- Log in as **admin**: Tamper-Evident Audit Trail (hash-chained, *not* a
  blockchain) and Passive Capture Agent (allowlisted dropdowns only — or the
  disabled-by-policy card when the optional agent is off).

## Close
Reiterate the honesty contract: unknown/encrypted is shown as unknown; scores
are withheld on insufficient evidence; ML traffic labels are probabilistic
inference, never payload inspection or guaranteed app identification.
