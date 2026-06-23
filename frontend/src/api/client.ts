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
  getCompliance: (framework: string) =>
    client.get(`/compliance/${framework}`),
};

export default client;
