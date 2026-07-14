import axios from 'axios';

const client = axios.create({
  baseURL: '/api/v1',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

client.interceptors.request.use((config) => {
  let key = localStorage.getItem('sovascan-active-key');
  
  const oldKeys = [
    'ss_live_z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4',
    'ss_live_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6'
  ];
  
  if (key && oldKeys.includes(key)) {
    localStorage.removeItem('sovascan-active-key');
    localStorage.removeItem('sovascan-api-keys');
    key = null;
  }

  if (!key) {
    try {
      const stored = localStorage.getItem('sovascan-api-keys');
      if (stored) {
        const parsed = JSON.parse(stored);
        if (Array.isArray(parsed) && parsed.length > 0) {
          key = parsed[0].key;
          localStorage.setItem('sovascan-active-key', key as string);
        }
      }
    } catch {
      // ignore
    }
  }
  
  if (key && oldKeys.includes(key)) {
    key = null;
  }

  if (!key) {
    key = 'ss_live_mock_local_dev_key_12345';
  }
  if (key) {
    config.headers['X-API-Key'] = key;
  }
  return config;
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
  applyFix: (
    findingId: string, 
    autoApply: boolean = true, 
    customReplacement?: string,
    contextReplacement?: string,
    contextStartLine?: number,
    contextEndLine?: number
  ) =>
    client.post(`/fix/${findingId}`, {
      finding_id: findingId,
      auto_apply: autoApply,
      custom_replacement: customReplacement,
      context_replacement: contextReplacement,
      context_start_line: contextStartLine,
      context_end_line: contextEndLine,
    }),

  /** POST /api/v1/fix/all — bulk fix all findings */
  fixAll: () => client.post('/fix/all'),

  /** POST /api/v1/scan/{scanId}/fix-all — bulk fix all findings in a scan */
  fixAllScan: (scanId: string) => client.post(`/scan/${scanId}/fix-all`),

  getCompliance: (framework: string, scanId?: string) =>
    client.get(`/compliance/${framework}`, { params: scanId ? { scan_id: scanId } : {} }),

  /** GET /api/v1/scan/{scanId}/sbom — retrieve SBOM packages for a scan */
  getSBOM: (scanId: string) => client.get(`/scan/${scanId}/sbom`),

  /** GET /api/v1/threat-intel/scan/{scanId} — retrieve threat intelligence statistics */
  getThreatIntel: (scanId: string) => client.get(`/threat-intel/scan/${scanId}`),

  /** GET /api/v1/findings/{findingId}/context — surrounding code context */
  getFindingContext: (findingId: string) =>
    client.get(`/findings/${findingId}/context`),

  /** POST /api/v1/findings/{findingId}/revert — revert applied fix */
  revertFix: (
    findingId: string,
    backupText: string,
    startLine: number,
    endLine: number
  ) =>
    client.post(`/findings/${findingId}/revert`, {
      finding_id: findingId,
      auto_apply: true,
      context_replacement: backupText,
      context_start_line: startLine,
      context_end_line: endLine,
    }),

  /** GET /api/v1/auth/api-keys — list metadata of API keys */
  getApiKeys: () => client.get('/auth/api-keys'),

  /** POST /api/v1/auth/api-keys — generate new API key */
  createApiKey: (name: string) => client.post('/auth/api-keys', { name }),

  /** DELETE /api/v1/auth/api-keys/{keyId} — revoke API key */
  deleteApiKey: (keyId: string) => client.delete(`/auth/api-keys/${keyId}`),
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
  const key = localStorage.getItem('sovascan-active-key') || 'ss_live_mock_local_dev_key_12345';
  const url = `${protocol}//${host}/api/v1/scan/${scanId}/ws?api_key=${encodeURIComponent(key)}`;
  return new WebSocket(url);
}

export default client;
