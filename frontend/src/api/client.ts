import axios from 'axios';

const client = axios.create({
  baseURL: '/api/v1',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

client.interceptors.response.use(
  (response) => response,
  (error) => {
    const message =
      error.response?.data?.detail ||
      error.response?.data?.message ||
      error.message ||
      'An unexpected error occurred';
    console.error('[API Error]', message);
    return Promise.reject(new Error(message));
  }
);

export const api = {
  /** GET /api/v1/dashboard/summary — aggregated dashboard metrics */
  getDashboard: () => client.get('/dashboard/summary'),

  /** GET /api/v1/scan — list all scans with pagination */
  getScans: (params?: { skip?: number; limit?: number }) =>
    client.get('/scan', { params }),

  /** GET /api/v1/scan/{id} — single scan by UUID */
  getScan: (id: string) => client.get(`/scan/${id}`),

  /** POST /api/v1/scan — create and run a new scan */
  createScan: (data: {
    target: string;
    scan_type: string;
    options?: Record<string, unknown>;
  }) => client.post('/scan', data),

  /** GET /api/v1/findings — list findings across all scans */
  getFindings: (params?: {
    scan_id?: string;
    severity?: string;
    category?: string;
    page?: number;
    per_page?: number;
  }) => client.get('/findings', { params }),

  /** POST /api/v1/fix/{findingId} — generate or apply an auto-fix */
  applyFix: (findingId: string, autoApply: boolean = true) =>
    client.post(`/fix/${findingId}`, {
      finding_id: findingId,
      auto_apply: autoApply,
    }),

  /** POST /api/v1/fix/all — bulk fix all findings */
  fixAll: () => client.post('/fix/all'),

  /** POST /api/v1/scan/{scanId}/fix-all — bulk fix all findings in a scan */
  fixAllScan: (scanId: string) => client.post(`/scan/${scanId}/fix-all`),

  /** GET /api/v1/compliance/{framework} — compliance report */
  getCompliance: (framework: string, scanId?: string) =>
    client.get(`/compliance/${framework}`, { params: scanId ? { scan_id: scanId } : {} }),

  /** GET /api/v1/scan/{scanId}/sbom — retrieve SBOM packages for a scan */
  getSBOM: (scanId: string) => client.get(`/scan/${scanId}/sbom`),

  /** GET /api/v1/threat-intel/scan/{scanId} — retrieve threat intelligence statistics */
  getThreatIntel: (scanId: string) => client.get(`/threat-intel/scan/${scanId}`),
};

/**
 * Create a WebSocket connection for real-time scan progress streaming.
 *
 * @param scanId - The UUID of the scan to stream progress for.
 * @returns A native WebSocket instance connected to the scan's WS endpoint.
 */
export function createScanWebSocket(scanId: string): WebSocket {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const host = window.location.host;
  const url = `${protocol}//${host}/api/v1/scan/${scanId}/ws`;
  return new WebSocket(url);
}

export default client;
