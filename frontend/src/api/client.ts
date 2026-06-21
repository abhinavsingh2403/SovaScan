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
  getDashboard: () => client.get('/dashboard'),
  getScans: (params?: { skip?: number; limit?: number }) =>
    client.get('/scans', { params }),
  getScan: (id: string) => client.get(`/scans/${id}`),
  createScan: (data: {
    target: string;
    scan_type: string;
    frameworks?: string[];
    max_depth?: number;
    exclude_patterns?: string[];
    timeout?: number;
  }) => client.post('/scans', data),
  getFindings: (params?: {
    scan_id?: string;
    severity?: string;
    category?: string;
    is_fixed?: boolean;
    skip?: number;
    limit?: number;
  }) => client.get('/findings', { params }),
  getFinding: (id: string) => client.get(`/findings/${id}`),
  updateFinding: (id: string, data: { is_fixed: boolean }) =>
    client.patch(`/findings/${id}`, data),
  getCompliance: (framework: string) =>
    client.get(`/compliance/${framework}`),
  exportCompliance: (framework: string, format: string) =>
    client.get(`/compliance/${framework}/export`, {
      params: { format },
      responseType: 'blob',
    }),
};

export default client;
