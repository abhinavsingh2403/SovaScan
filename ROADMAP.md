# 🗺️ SovaScan — Developer Roadmap & Implementation Guide

Welcome! SovaScan is an intelligent dependency & configuration security analyzer designed for financial and banking codebases. 

This document outlines the **current project status**, lists **what is mocked or stubbed**, and details **what needs to be built/fixed** by incoming developers to make the system fully functional and ready for production.

---

## 🟢 1. What is Implemented & Working

### Backend Engine & Core CLI (`backend/sovascan`)
- **CLI Analyzer**: The Click-based CLI (`sovascan scan <path>`) is fully operational. It runs local scans, parses manifest files, checks for hardcoded keys and configuration misconfigurations, maps findings contextually using banking keywords, and outputs a formatted terminal report.
- **SQLAlchemy Database**: Core schemas for `Scan` and `Finding` rows are fully defined.
- **FastAPI Infrastructure**: A complete REST routing framework is operational, with unit test suites passing.

### Frontend UI Dashboard (`frontend/`)
- **Interface Screens**: Complete layout, sidebar navigation, findings explorer, compliance checklists, and dashboard visual cards.
- **Production Build**: Compiles cleanly using Vite and Tailwind-alternative CSS properties.

---

## 🟡 2. What is Mocked, Stubbed, or Not Working

Currently, several components use temporary stubs or mocks to decouple the frontend and backend development:

### A. API Scans do not trigger the real scanner
- **Location**: `backend/sovascan/api/routes.py` (inside the `_run_scan_logic` helper).
- **Behavior**: When you trigger a scan via the API (`POST /api/v1/scan`), the route handler uses a mock checker that returns three hardcoded findings. It does not run the actual `ScanOrchestrator` on the path.

### B. Scans run synchronously
- **Behavior**: Scans run blocking-style in the API request thread. For large directories, this will lead to HTTP gateway timeouts. There is currently no asynchronous task queue configured.

### C. Frontend displays mock data only
- **Location**: `frontend/src/store/index.ts`
- **Behavior**: The Zustand store actions (`fetchDashboard`, `fetchScans`, `fetchFindings`) use local setTimeout loops with static mock arrays. The UI does not display data from the SQLite database.
- **Scan Progress Screen**: The progress bar uses a client-side mock `setInterval` loop to increment percentages rather than receiving actual backend scan stages.

---

## 🛠️ 3. Implementation To-Do List (What to Fix & Build)

Here are the step-by-step tasks required to make SovaScan complete:

### Task 1: Connect Frontend Zustand Store to API Client
- **File to Edit**: `frontend/src/store/index.ts`
- **What to do**:
  1. Import the axios client from `../api/client`.
  2. Replace the simulated `setTimeout` in `fetchDashboard`, `fetchScans`, and `fetchFindings` with actual backend requests:
     - `fetchDashboard()` ➔ `GET /api/v1/dashboard/summary`
     - `fetchScans()` ➔ `GET /api/v1/scan/...`
     - `fetchFindings()` ➔ `GET /api/v1/scan/{scan_id}/findings`
  3. Ensure that when a scan finishes, the Zustand state is updated and the lists refresh automatically.

### Task 2: Connect backend API scan route to the actual Scanner Orchestrator
- **File to Edit**: `backend/sovascan/api/routes.py`
- **What to do**:
  1. Modify `_run_scan_logic(target, scan_type, options)` to import and run `ScanOrchestrator`.
  2. Run `orchestrator = ScanOrchestrator(target_path=target, scan_type=scan_type)` and return the list of findings.
  3. Save the findings to the database under the created `Scan` UUID.

### Task 3: Implement Asynchronous Scanning (Celery & Redis)
- **Goal**: Scans should execute as background tasks so the API stays responsive.
- **What to do**:
  1. Uncomment the Redis service block in `docker-compose.yml`.
  2. Initialize a Celery app in the backend (e.g. `sovascan/worker.py`).
  3. Wrap the orchestrator run step inside a Celery task:
     ```python
     @celery.task
     def run_background_scan(scan_id: str, target: str, scan_type: str):
         # Run scan, update database record status to COMPLETED/FAILED
     ```
  4. In `routes.py`, change `POST /scan` to dispatch the task: `run_background_scan.delay(...)` and immediately return the scan details with status `RUNNING`.

### Task 4: Connect Live Scan Progress (WebSockets)
- **Goal**: Make the frontend progress bar show real-time phases instead of client-side loops.
- **What to do**:
  1. Create a FastAPI WebSocket route: `websocket("/ws/scan/{scan_id}")`.
  2. Modify the `ScanOrchestrator`'s `progress_callback` to publish progress updates (phase and percentage) to a redis channel or directly to active websocket sessions.
  3. On the frontend (`pages/Scan.tsx`), open a WebSocket connection when starting a scan to receive state updates and render the progress bar dynamically.

### Task 5: Upgrade Rules to Abstract Syntax Tree (AST) Parsing
- **Goal**: Eliminate false positives in configuration checks (e.g., regex matching commented-out lines).
- **What to do**:
  1. In `core/misconfig_detector.py`, instead of doing basic line-by-line regex checks on configuration files:
     - Use Python's built-in `ast` module to inspect imports and function calls when scanning Python targets.
     - Integrate structured YAML/JSON parsers for infrastructure configs (like checking JSON structures for wildcard CORS rather than regex string matching).

### Task 6: Deploy PostgreSQL database
- **Goal**: Shift from SQLite to a scalable database engine.
- **What to do**:
  1. Uncomment the Postgres configuration block in `docker-compose.yml`.
  2. Swap the `DATABASE_URL` environment setting to point to the Postgres container. SQLAlchemy models will automatically adapt to PostgreSQL.
