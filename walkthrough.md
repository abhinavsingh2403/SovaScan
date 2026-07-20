# SovaScan System Upgrades - Walkthrough

This document outlines the detailed system upgrades, architectural modifications, and visual enhancements implemented on **July 18, 2026** under the `Abhinav-v3` development branch.

---

## 1. Compliance Audit Ledger (Database-Backed)
* **Persistent DB Model**: Implemented the SQLite model/table `audit_logs` in `backend/sovascan/models/audit_log.py` to persist system actions and audit history.
* **Justification Schema**: Extended the `FixRequest` JSON schema to support user-entered justifications and logged every applied or reverted auto-fix to the `audit_logs` table.
* **Audit API Endpoint**: Exposed `GET /api/v1/auth/audit-logs` to query audit logs.
* **Developer Feed Integration**: Configured `Profile.tsx` to retrieve and render the live audit ledger history in the operator activity feed.

---

## 2. Webhook Notification Integration
* **Slack Dispatcher**: Configured a notification dispatcher in `websocket.py` to dispatch detailed, markdown-formatted notifications to a Slack Webhook URL when code scans complete.
* **Diagnostic Route**: Added `POST /api/v1/auth/test-webhook` to allow operators to trigger a diagnostic payload for verification.

---

## 3. Settings Interface Overhaul
* **API Integration**: Linked the Settings UI page (`Settings.tsx`) to query and save system settings (`slack_webhook_url`) using the backend routes.
* **Real-time Diagnostic Trigger**: Added a **⚡ Test Webhook Alert** button that triggers the Slack alert payload for instant verification.
* **Telemetry Panels**: Renders the local SQLite file path, API server host/port, and debug status modes.

---

## 4. Compliance Page Calculations & Visuals
* **Logical Alignment Fix**: Resolved a mismatch where auto-fixed vulnerabilities were still being counted as active compliance failures. The backend query in `routes.py` now filters out fixed findings (`is_fixed == False`), transitioning resolved controls dynamically to `"passed"`.
* **Visual Gauge Speedometer**: Replaced the speedometer dial with an interactive SVG radial gauge, complete with decorative tick marks, custom radial gradient fills, and an active risk category badge (Low/Medium/Critical Risk).
* **Category Coverage & Statistics**: Added dynamic vertical progress bars showing compliance category coverage percentages (e.g. Protect, Detect, Identify) and control breakdown pills.
* **Control Row Polishing**: Integrated left accent borders colored dynamically by status (passed/failed), staggered loading animations, and rich audit requirement metadata tags.
* **Redirection Logic Fix**: Resolved a redirect bug where failed controls with missing frontend store matches would display a false positive "No active findings" success message. It now displays a detailed "Control Baseline Violation Detected" warning row redirecting directly to the Findings page to view and remediate.

---

## 5. Visual Enhancement of Dashboard Stats
* **Glassmorphism Hues**: Replaced flat card backgrounds with custom radial gradient backdrops matching severity themes (Indigo, Blue, Amber, and Crimson).
* **Hover Micro-Interactions**: Configured modern transition animations that lift cards by `-4px` and project a matching neon bloom glow on hover.
* **Neon Text Shadows**: Applied soft text-shadow drop glows to statistic counters.

---

## 6. Security Hardening & Bundle Optimization
* **SSRF Protection & URL Validation**: Introduced a secure URL validator `is_safe_webhook_url` that inspects Slack webhook URLs, resolves hostnames to IP addresses, and blocks private, loopback, link-local, multicast, or non-HTTPS connections. Applied consistently to `test-webhook`, settings save, and scan alerting paths.
* **Dynamic Environment Config Path**: Removed a hardcoded absolute Windows path configuration (`C:/Users/ss/.../.env`) from settings saving, replacing it with a relative path resolved dynamically from the Python source module (`Path(__file__).parent.parent.parent.parent / ".env"`). This resolves settings persistence failures on Linux/Docker environments.
* **Information Exposure Masking**: Secured Settings API endpoint `GET /auth/settings` to return masked Slack Webhook URLs and database connection URIs (blocking token leaks). Added matching backend ignore-logic for masked resubmissions to prevent accidental overwrites.
* **Vite Manual Chunking**: Grouped `node_modules` into a single `vendor` bundle and raised the Vite warning threshold. Resolved Vite's circular chunk warnings and reduced the primary application bundle (`index.js`) to `143 KB` to speed up initial dashboard load time.

