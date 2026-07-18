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
* **Visual Gauge & Radar**: Retained the Recharts `RadarChart` inside the left sidebar panel of the 2-column layout to visualize category compliance scores dynamically.

---

## 5. Visual Enhancement of Dashboard Stats
* **Glassmorphism Hues**: Replaced flat card backgrounds with custom radial gradient backdrops matching severity themes (Indigo, Blue, Amber, and Crimson).
* **Hover Micro-Interactions**: Configured modern transition animations that lift cards by `-4px` and project a matching neon bloom glow on hover.
* **Neon Text Shadows**: Applied soft text-shadow drop glows to statistic counters.
