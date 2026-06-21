import { create } from 'zustand';
import type {
  Scan,
  Finding,
  DashboardSummary,
  ComplianceReport,
  ComplianceControl,
} from '../types';

/* ============================================================
   Mock Data
   ============================================================ */

const mockScans: Scan[] = [
  {
    id: 'scan-001',
    target: '/app/services/payment-gateway',
    status: 'completed',
    scanType: 'full',
    totalFindings: 47,
    criticalCount: 3,
    highCount: 8,
    mediumCount: 18,
    lowCount: 14,
    startedAt: '2026-06-12T09:30:00Z',
    completedAt: '2026-06-12T09:42:18Z',
    createdAt: '2026-06-12T09:29:55Z',
  },
  {
    id: 'scan-002',
    target: '/app/services/auth-service',
    status: 'completed',
    scanType: 'full',
    totalFindings: 32,
    criticalCount: 1,
    highCount: 5,
    mediumCount: 14,
    lowCount: 12,
    startedAt: '2026-06-11T14:00:00Z',
    completedAt: '2026-06-11T14:11:42Z',
    createdAt: '2026-06-11T13:59:30Z',
  },
  {
    id: 'scan-003',
    target: '/app/infrastructure/terraform',
    status: 'completed',
    scanType: 'misconfig',
    totalFindings: 21,
    criticalCount: 2,
    highCount: 6,
    mediumCount: 9,
    lowCount: 4,
    startedAt: '2026-06-11T10:15:00Z',
    completedAt: '2026-06-11T10:19:33Z',
    createdAt: '2026-06-11T10:14:48Z',
  },
  {
    id: 'scan-004',
    target: '/app/services/user-service',
    status: 'running',
    scanType: 'dependencies',
    totalFindings: 15,
    criticalCount: 0,
    highCount: 3,
    mediumCount: 7,
    lowCount: 5,
    startedAt: '2026-06-12T16:30:00Z',
    completedAt: null,
    createdAt: '2026-06-12T16:29:50Z',
  },
  {
    id: 'scan-005',
    target: '/app/services/notification-service',
    status: 'completed',
    scanType: 'secrets',
    totalFindings: 8,
    criticalCount: 4,
    highCount: 2,
    mediumCount: 1,
    lowCount: 1,
    startedAt: '2026-06-10T08:45:00Z',
    completedAt: '2026-06-10T08:48:22Z',
    createdAt: '2026-06-10T08:44:50Z',
  },
  {
    id: 'scan-006',
    target: '/app/frontend/web-portal',
    status: 'completed',
    scanType: 'full',
    totalFindings: 28,
    criticalCount: 0,
    highCount: 4,
    mediumCount: 12,
    lowCount: 12,
    startedAt: '2026-06-09T11:20:00Z',
    completedAt: '2026-06-09T11:35:10Z',
    createdAt: '2026-06-09T11:19:45Z',
  },
  {
    id: 'scan-007',
    target: '/app/services/api-gateway',
    status: 'failed',
    scanType: 'full',
    totalFindings: 0,
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    startedAt: '2026-06-08T15:00:00Z',
    completedAt: '2026-06-08T15:01:05Z',
    createdAt: '2026-06-08T14:59:50Z',
  },
];

const mockFindings: Finding[] = [
  {
    id: 'find-001',
    scanId: 'scan-001',
    ruleId: 'SEC-SQL-001',
    title: 'SQL Injection in User Query Parameter',
    description:
      'User-supplied input is directly concatenated into an SQL query string without proper parameterization or escaping. This allows an attacker to inject arbitrary SQL commands, potentially leading to unauthorized data access, modification, or deletion.',
    severity: 'critical',
    category: 'Injection',
    filePath: 'src/controllers/userController.ts',
    lineNumber: 47,
    evidence:
      'const query = `SELECT * FROM users WHERE id = ${req.params.id}`;',
    remediation:
      'Use parameterized queries or an ORM. Replace string concatenation with prepared statements: db.query("SELECT * FROM users WHERE id = $1", [req.params.id])',
    cveId: 'CVE-2024-1234',
    cvssScore: 9.8,
    isFixed: false,
    createdAt: '2026-06-12T09:35:00Z',
  },
  {
    id: 'find-002',
    scanId: 'scan-001',
    ruleId: 'SEC-AUTH-002',
    title: 'Hardcoded JWT Secret Key',
    description:
      'A JWT secret key is hardcoded directly in the source code. If the repository is compromised or shared, attackers can forge authentication tokens and gain unauthorized access to the system.',
    severity: 'critical',
    category: 'Secrets',
    filePath: 'src/config/auth.ts',
    lineNumber: 12,
    evidence:
      'const JWT_SECRET = "super_secret_key_do_not_share_2024";',
    remediation:
      'Move the JWT secret to environment variables. Use process.env.JWT_SECRET and inject the value at runtime through a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.).',
    cveId: null,
    cvssScore: 9.1,
    isFixed: false,
    createdAt: '2026-06-12T09:35:12Z',
  },
  {
    id: 'find-003',
    scanId: 'scan-001',
    ruleId: 'SEC-XSS-001',
    title: 'Reflected Cross-Site Scripting (XSS)',
    description:
      'User input from the query string is reflected directly into the HTML response without sanitization. This enables reflected XSS attacks where malicious scripts execute in victim browsers.',
    severity: 'high',
    category: 'XSS',
    filePath: 'src/views/search.tsx',
    lineNumber: 23,
    evidence:
      '<div dangerouslySetInnerHTML={{ __html: searchQuery }} />',
    remediation:
      'Never use dangerouslySetInnerHTML with unsanitized user input. Use a library like DOMPurify to sanitize HTML, or render as plain text using React text content.',
    cveId: 'CVE-2024-2345',
    cvssScore: 7.5,
    isFixed: false,
    createdAt: '2026-06-12T09:35:30Z',
  },
  {
    id: 'find-004',
    scanId: 'scan-001',
    ruleId: 'SEC-DEP-001',
    title: 'Vulnerable Dependency: lodash@4.17.15',
    description:
      'The lodash package version 4.17.15 contains a known Prototype Pollution vulnerability (CVE-2020-8203) that allows attackers to modify JavaScript object prototypes.',
    severity: 'high',
    category: 'Dependencies',
    filePath: 'package.json',
    lineNumber: 24,
    evidence: '"lodash": "^4.17.15"',
    remediation:
      'Upgrade lodash to version 4.17.21 or later. Run: npm install lodash@latest',
    cveId: 'CVE-2020-8203',
    cvssScore: 7.4,
    isFixed: false,
    createdAt: '2026-06-12T09:36:00Z',
  },
  {
    id: 'find-005',
    scanId: 'scan-001',
    ruleId: 'SEC-CRYPTO-001',
    title: 'Weak Cryptographic Algorithm (MD5)',
    description:
      'MD5 is used for hashing passwords. MD5 is cryptographically broken and computationally feasible to reverse via rainbow tables and collision attacks.',
    severity: 'high',
    category: 'Cryptography',
    filePath: 'src/utils/crypto.ts',
    lineNumber: 8,
    evidence:
      'const hash = crypto.createHash("md5").update(password).digest("hex");',
    remediation:
      'Replace MD5 with bcrypt, scrypt, or Argon2 for password hashing. Use bcrypt.hash(password, 12) for a minimum of 12 salt rounds.',
    cveId: null,
    cvssScore: 7.2,
    isFixed: true,
    createdAt: '2026-06-12T09:36:15Z',
  },
  {
    id: 'find-006',
    scanId: 'scan-001',
    ruleId: 'SEC-MISCONF-001',
    title: 'CORS Wildcard Origin Allowed',
    description:
      'The CORS configuration allows requests from any origin (*). This can expose the API to cross-origin attacks and data exfiltration.',
    severity: 'medium',
    category: 'Misconfiguration',
    filePath: 'src/config/server.ts',
    lineNumber: 15,
    evidence: 'app.use(cors({ origin: "*" }));',
    remediation:
      'Restrict CORS origins to trusted domains only. Use an allowlist: cors({ origin: ["https://app.example.com"] })',
    cveId: null,
    cvssScore: 5.3,
    isFixed: false,
    createdAt: '2026-06-12T09:36:30Z',
  },
  {
    id: 'find-007',
    scanId: 'scan-001',
    ruleId: 'SEC-HEADER-001',
    title: 'Missing Content-Security-Policy Header',
    description:
      'The application does not set a Content-Security-Policy (CSP) header. Without CSP, the application is more susceptible to XSS and data injection attacks.',
    severity: 'medium',
    category: 'Headers',
    filePath: 'src/middleware/security.ts',
    lineNumber: 1,
    evidence: '// No CSP header configured in security middleware',
    remediation:
      'Add a Content-Security-Policy header using helmet middleware: app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: ["\'self\'"], scriptSrc: ["\'self\'"] } }))',
    cveId: null,
    cvssScore: 5.0,
    isFixed: false,
    createdAt: '2026-06-12T09:36:45Z',
  },
  {
    id: 'find-008',
    scanId: 'scan-001',
    ruleId: 'SEC-LOG-001',
    title: 'Sensitive Data in Log Output',
    description:
      'Passwords and authentication tokens are being logged to application logs. This exposes sensitive credentials in log files and monitoring systems.',
    severity: 'medium',
    category: 'Information Disclosure',
    filePath: 'src/services/authService.ts',
    lineNumber: 34,
    evidence:
      'logger.info(`User login: ${email}, password: ${password}`);',
    remediation:
      'Never log sensitive data. Redact passwords and tokens: logger.info(`User login: ${email}, password: [REDACTED]`)',
    cveId: null,
    cvssScore: 4.8,
    isFixed: true,
    createdAt: '2026-06-12T09:37:00Z',
  },
  {
    id: 'find-009',
    scanId: 'scan-003',
    ruleId: 'SEC-IAM-001',
    title: 'Overly Permissive IAM Policy (S3 Full Access)',
    description:
      'An IAM role is configured with s3:* permissions on all resources. This violates the principle of least privilege and could allow unauthorized data access across all S3 buckets.',
    severity: 'critical',
    category: 'IAM',
    filePath: 'terraform/modules/iam/main.tf',
    lineNumber: 22,
    evidence:
      'effect = "Allow"\nactions = ["s3:*"]\nresources = ["*"]',
    remediation:
      'Restrict IAM policies to specific actions and resources. Use: actions = ["s3:GetObject", "s3:PutObject"] and resources = ["arn:aws:s3:::my-bucket/*"]',
    cveId: null,
    cvssScore: 8.8,
    isFixed: false,
    createdAt: '2026-06-11T10:16:00Z',
  },
  {
    id: 'find-010',
    scanId: 'scan-003',
    ruleId: 'SEC-TF-001',
    title: 'S3 Bucket Without Server-Side Encryption',
    description:
      'An S3 bucket is configured without server-side encryption enabled. Data stored in this bucket is not encrypted at rest, potentially exposing sensitive information.',
    severity: 'high',
    category: 'Misconfiguration',
    filePath: 'terraform/modules/storage/s3.tf',
    lineNumber: 8,
    evidence:
      'resource "aws_s3_bucket" "data" {\n  bucket = "prod-data-bucket"\n  # No server_side_encryption_configuration block\n}',
    remediation:
      'Add server-side encryption configuration:\nserver_side_encryption_configuration {\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = "aws:kms"\n    }\n  }\n}',
    cveId: null,
    cvssScore: 6.5,
    isFixed: false,
    createdAt: '2026-06-11T10:16:30Z',
  },
  {
    id: 'find-011',
    scanId: 'scan-002',
    ruleId: 'SEC-AUTH-003',
    title: 'Missing Rate Limiting on Login Endpoint',
    description:
      'The /api/auth/login endpoint does not implement rate limiting. Attackers can perform brute-force attacks to guess user credentials without being throttled.',
    severity: 'high',
    category: 'Authentication',
    filePath: 'src/routes/auth.ts',
    lineNumber: 15,
    evidence:
      'router.post("/login", authController.login); // No rate limiter middleware',
    remediation:
      'Add rate limiting middleware: router.post("/login", rateLimit({ windowMs: 15*60*1000, max: 5 }), authController.login)',
    cveId: null,
    cvssScore: 7.1,
    isFixed: false,
    createdAt: '2026-06-11T14:05:00Z',
  },
  {
    id: 'find-012',
    scanId: 'scan-005',
    ruleId: 'SEC-SECRET-001',
    title: 'AWS Access Key Exposed in Source Code',
    description:
      'An AWS Access Key ID and Secret Access Key are hardcoded in the source code. These credentials could be used to gain unauthorized access to AWS services.',
    severity: 'critical',
    category: 'Secrets',
    filePath: 'src/config/aws.ts',
    lineNumber: 5,
    evidence:
      'const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";\nconst AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";',
    remediation:
      'Remove hardcoded credentials immediately. Rotate the compromised keys. Use IAM roles for EC2/ECS or environment variables injected from a secrets manager.',
    cveId: null,
    cvssScore: 9.5,
    isFixed: false,
    createdAt: '2026-06-10T08:46:00Z',
  },
  {
    id: 'find-013',
    scanId: 'scan-001',
    ruleId: 'SEC-PATH-001',
    title: 'Path Traversal in File Download',
    description:
      'The file download endpoint uses user input to construct file paths without sanitization. An attacker can use ../ sequences to access files outside the intended directory.',
    severity: 'high',
    category: 'Injection',
    filePath: 'src/controllers/fileController.ts',
    lineNumber: 19,
    evidence:
      'const filePath = path.join(UPLOAD_DIR, req.params.filename);',
    remediation:
      'Validate and sanitize file paths. Use path.normalize() and verify the resolved path starts with the intended directory: if (!resolvedPath.startsWith(UPLOAD_DIR)) throw new ForbiddenError()',
    cveId: 'CVE-2024-3456',
    cvssScore: 7.8,
    isFixed: false,
    createdAt: '2026-06-12T09:37:15Z',
  },
  {
    id: 'find-014',
    scanId: 'scan-006',
    ruleId: 'SEC-DEP-002',
    title: 'Vulnerable Dependency: axios@0.21.0',
    description:
      'axios version 0.21.0 is vulnerable to Server-Side Request Forgery (SSRF). An attacker can exploit this to make the server send requests to unintended targets.',
    severity: 'medium',
    category: 'Dependencies',
    filePath: 'package.json',
    lineNumber: 18,
    evidence: '"axios": "^0.21.0"',
    remediation:
      'Upgrade axios to version 0.21.2 or later. Run: npm install axios@latest',
    cveId: 'CVE-2021-3749',
    cvssScore: 5.9,
    isFixed: true,
    createdAt: '2026-06-09T11:25:00Z',
  },
  {
    id: 'find-015',
    scanId: 'scan-001',
    ruleId: 'SEC-SESS-001',
    title: 'Session Cookie Without Secure Flag',
    description:
      'Session cookies are set without the Secure flag, allowing them to be transmitted over unencrypted HTTP connections. This can expose session tokens to man-in-the-middle attacks.',
    severity: 'medium',
    category: 'Session Management',
    filePath: 'src/config/session.ts',
    lineNumber: 9,
    evidence:
      'cookie: { httpOnly: true, sameSite: "lax" } // missing secure: true',
    remediation:
      'Set the secure flag on session cookies: cookie: { httpOnly: true, secure: true, sameSite: "strict" }',
    cveId: null,
    cvssScore: 4.3,
    isFixed: false,
    createdAt: '2026-06-12T09:37:30Z',
  },
  {
    id: 'find-016',
    scanId: 'scan-003',
    ruleId: 'SEC-TF-002',
    title: 'Security Group Allows Unrestricted SSH Access',
    description:
      'An AWS Security Group ingress rule allows SSH (port 22) access from all IP addresses (0.0.0.0/0). This exposes the instances to brute-force attacks from the internet.',
    severity: 'high',
    category: 'Misconfiguration',
    filePath: 'terraform/modules/network/security_groups.tf',
    lineNumber: 14,
    evidence:
      'ingress {\n  from_port = 22\n  to_port = 22\n  protocol = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}',
    remediation:
      'Restrict SSH access to specific trusted IP ranges or use AWS Systems Manager Session Manager instead of direct SSH access.',
    cveId: null,
    cvssScore: 6.8,
    isFixed: false,
    createdAt: '2026-06-11T10:17:00Z',
  },
  {
    id: 'find-017',
    scanId: 'scan-002',
    ruleId: 'SEC-IDOR-001',
    title: 'Insecure Direct Object Reference (IDOR)',
    description:
      'The API endpoint retrieves user records using sequential numeric IDs without verifying the requesting user has authorization to access the record.',
    severity: 'medium',
    category: 'Authorization',
    filePath: 'src/controllers/profileController.ts',
    lineNumber: 28,
    evidence:
      'const profile = await Profile.findById(req.params.id); // No ownership check',
    remediation:
      'Implement proper authorization checks: verify req.user.id matches the resource owner or the user has admin privileges.',
    cveId: null,
    cvssScore: 5.5,
    isFixed: false,
    createdAt: '2026-06-11T14:06:00Z',
  },
  {
    id: 'find-018',
    scanId: 'scan-001',
    ruleId: 'SEC-ERR-001',
    title: 'Verbose Error Messages in Production',
    description:
      'The application returns detailed stack traces and internal error messages to clients in production mode. This can reveal implementation details useful for attackers.',
    severity: 'low',
    category: 'Information Disclosure',
    filePath: 'src/middleware/errorHandler.ts',
    lineNumber: 10,
    evidence:
      'res.status(500).json({ error: err.message, stack: err.stack });',
    remediation:
      'In production, return generic error messages: res.status(500).json({ error: "Internal server error" }). Log detailed errors server-side only.',
    cveId: null,
    cvssScore: 3.5,
    isFixed: false,
    createdAt: '2026-06-12T09:37:45Z',
  },
  {
    id: 'find-019',
    scanId: 'scan-006',
    ruleId: 'SEC-REACT-001',
    title: 'React State Contains Sensitive Token',
    description:
      'An authentication token is stored in React component state and persisted to localStorage without encryption. Browser extensions and XSS attacks can extract these tokens.',
    severity: 'low',
    category: 'Client-Side Security',
    filePath: 'src/hooks/useAuth.tsx',
    lineNumber: 15,
    evidence:
      'localStorage.setItem("authToken", token);',
    remediation:
      'Use httpOnly cookies for token storage instead of localStorage. If localStorage must be used, implement token rotation and short expiry times.',
    cveId: null,
    cvssScore: 3.8,
    isFixed: false,
    createdAt: '2026-06-09T11:28:00Z',
  },
  {
    id: 'find-020',
    scanId: 'scan-005',
    ruleId: 'SEC-SECRET-002',
    title: 'Database Connection String with Credentials',
    description:
      'A MongoDB connection string with embedded username and password is hardcoded in the application source code.',
    severity: 'critical',
    category: 'Secrets',
    filePath: 'src/config/database.ts',
    lineNumber: 3,
    evidence:
      'const MONGO_URI = "mongodb://admin:P@ssw0rd123@prod-db.internal:27017/sovascan";',
    remediation:
      'Remove hardcoded credentials. Use environment variables: process.env.MONGO_URI. Store the connection string in a secrets manager.',
    cveId: null,
    cvssScore: 9.0,
    isFixed: false,
    createdAt: '2026-06-10T08:47:00Z',
  },
];

const mockDashboard: DashboardSummary = {
  totalScans: 42,
  totalFindings: 284,
  riskScore: 72,
  severityDistribution: {
    critical: 14,
    high: 38,
    medium: 96,
    low: 102,
    info: 34,
  },
  recentScans: mockScans.slice(0, 5),
  topVulnerabilities: [
    { id: '1', title: 'SQL Injection', severity: 'critical', count: 7, category: 'Injection' },
    { id: '2', title: 'Hardcoded Secrets', severity: 'critical', count: 12, category: 'Secrets' },
    { id: '3', title: 'Cross-Site Scripting', severity: 'high', count: 9, category: 'XSS' },
    { id: '4', title: 'Outdated Dependencies', severity: 'high', count: 23, category: 'Dependencies' },
    { id: '5', title: 'Misconfigured CORS', severity: 'medium', count: 6, category: 'Misconfiguration' },
  ],
  trendData: [
    { date: '2026-05-13', critical: 18, high: 45, medium: 102, low: 115 },
    { date: '2026-05-20', critical: 16, high: 42, medium: 98, low: 110 },
    { date: '2026-05-27', critical: 15, high: 40, medium: 95, low: 108 },
    { date: '2026-06-03', critical: 14, high: 39, medium: 97, low: 105 },
    { date: '2026-06-10', critical: 14, high: 38, medium: 96, low: 102 },
    { date: '2026-06-12', critical: 14, high: 38, medium: 96, low: 102 },
  ],
};

const makeControls = (framework: string): ComplianceControl[] => {
  const cats: Record<string, string[]> = {
    'RBI-CSF': [
      'Governance', 'Governance', 'Identify', 'Identify', 'Protect', 'Protect',
      'Protect', 'Detect', 'Detect', 'Respond', 'Respond', 'Recover',
    ],
    'PCI-DSS': [
      'Network Security', 'Network Security', 'Data Protection', 'Data Protection',
      'Vulnerability Management', 'Vulnerability Management', 'Access Control',
      'Access Control', 'Monitoring', 'Monitoring', 'Security Policy', 'Security Policy',
    ],
    'ISO-27001': [
      'Information Security Policies', 'Organization of InfoSec', 'Human Resource Security',
      'Asset Management', 'Access Control', 'Cryptography', 'Physical Security',
      'Operations Security', 'Communications Security', 'System Acquisition',
      'Supplier Relationships', 'Incident Management',
    ],
  };
  const names: Record<string, string[]> = {
    'RBI-CSF': [
      'Cyber Security Policy', 'Board Oversight', 'Asset Inventory',
      'Risk Assessment', 'Access Control Management', 'Data Protection',
      'Network Security', 'SOC Monitoring', 'Anomaly Detection',
      'Incident Response Plan', 'Communication Protocol', 'Recovery Planning',
    ],
    'PCI-DSS': [
      'Firewall Configuration', 'Default Password Policy', 'Cardholder Data Encryption',
      'Data Retention Policy', 'Anti-Virus Deployment', 'Secure Development',
      'Role-Based Access', 'Unique User IDs', 'Audit Trail Logging',
      'Security Monitoring', 'InfoSec Policy', 'Risk Assessment Process',
    ],
    'ISO-27001': [
      'Security Policy Document', 'InfoSec Roles', 'Employee Screening',
      'Asset Classification', 'User Access Management', 'Key Management',
      'Secure Areas', 'Change Management', 'Network Controls',
      'Security in Development', 'Supplier Policy', 'Incident Procedures',
    ],
  };
  const fwCats = cats[framework] || cats['RBI-CSF'];
  const fwNames = names[framework] || names['RBI-CSF'];
  return fwNames.map((name, i) => {
    const statuses: Array<'passed' | 'failed' | 'not-applicable'> = [
      'passed', 'passed', 'passed', 'failed', 'passed', 'passed',
      'failed', 'passed', 'passed', 'failed', 'passed', 'not-applicable',
    ];
    return {
      id: `${framework}-${String(i + 1).padStart(3, '0')}`,
      name,
      description: `Ensure ${name.toLowerCase()} is properly implemented and maintained.`,
      status: statuses[i],
      category: fwCats[i],
      findings: statuses[i] === 'failed' ? [`find-${String(i + 1).padStart(3, '0')}`] : [],
    };
  });
};

const mockComplianceReports: Record<string, ComplianceReport> = {
  'RBI-CSF': {
    framework: 'RBI-CSF',
    frameworkFullName: 'RBI Cyber Security Framework',
    score: 78,
    totalControls: 12,
    passed: 8,
    failed: 3,
    notApplicable: 1,
    controls: makeControls('RBI-CSF'),
    lastAssessed: '2026-06-12T09:42:18Z',
  },
  'PCI-DSS': {
    framework: 'PCI-DSS',
    frameworkFullName: 'Payment Card Industry Data Security Standard',
    score: 85,
    totalControls: 12,
    passed: 9,
    failed: 3,
    notApplicable: 0,
    controls: makeControls('PCI-DSS'),
    lastAssessed: '2026-06-11T14:11:42Z',
  },
  'ISO-27001': {
    framework: 'ISO-27001',
    frameworkFullName: 'ISO/IEC 27001 Information Security',
    score: 71,
    totalControls: 12,
    passed: 8,
    failed: 3,
    notApplicable: 1,
    controls: makeControls('ISO-27001'),
    lastAssessed: '2026-06-11T10:19:33Z',
  },
};

/* ============================================================
   Store
   ============================================================ */

interface SovaState {
  scans: Scan[];
  findings: Finding[];
  dashboardSummary: DashboardSummary | null;
  complianceReports: Record<string, ComplianceReport>;
  loading: boolean;
  error: string | null;
  selectedScan: Scan | null;
  scanProgress: {
    running: boolean;
    phase: string;
    percent: number;
    findingsCount: number;
  };

  fetchDashboard: () => void;
  fetchScans: () => void;
  fetchFindings: () => void;
  startScan: (target: string, scanType: string, frameworks: string[]) => void;
  selectScan: (scan: Scan | null) => void;
  getComplianceReport: (framework: string) => ComplianceReport | null;
}

export const useStore = create<SovaState>((set, get) => ({
  scans: [],
  findings: [],
  dashboardSummary: null,
  complianceReports: mockComplianceReports,
  loading: false,
  error: null,
  selectedScan: null,
  scanProgress: {
    running: false,
    phase: '',
    percent: 0,
    findingsCount: 0,
  },

  fetchDashboard: () => {
    set({ loading: true });
    setTimeout(() => {
      set({ dashboardSummary: mockDashboard, loading: false });
    }, 400);
  },

  fetchScans: () => {
    set({ loading: true });
    setTimeout(() => {
      set({ scans: mockScans, loading: false });
    }, 300);
  },

  fetchFindings: () => {
    set({ loading: true });
    setTimeout(() => {
      set({ findings: mockFindings, loading: false });
    }, 350);
  },

  startScan: (target: string, _scanType: string, _frameworks: string[]) => {
    const phases = ['Discovering', 'Resolving', 'Scanning', 'Scoring', 'Reporting'];
    let phaseIdx = 0;
    let percent = 0;

    set({
      scanProgress: { running: true, phase: phases[0], percent: 0, findingsCount: 0 },
    });

    const interval = setInterval(() => {
      percent += Math.random() * 8 + 3;
      if (percent >= 100) percent = 100;

      const newPhaseIdx = Math.min(Math.floor(percent / 20), phases.length - 1);
      if (newPhaseIdx !== phaseIdx) phaseIdx = newPhaseIdx;

      const fc = Math.floor(percent * 0.47);

      set({
        scanProgress: {
          running: percent < 100,
          phase: phases[phaseIdx],
          percent: Math.min(Math.round(percent), 100),
          findingsCount: fc,
        },
      });

      if (percent >= 100) {
        clearInterval(interval);
        const newScan: Scan = {
          id: `scan-${Date.now()}`,
          target,
          status: 'completed',
          scanType: 'full',
          totalFindings: fc,
          criticalCount: Math.floor(fc * 0.07),
          highCount: Math.floor(fc * 0.17),
          mediumCount: Math.floor(fc * 0.38),
          lowCount: Math.floor(fc * 0.38),
          startedAt: new Date(Date.now() - 720000).toISOString(),
          completedAt: new Date().toISOString(),
          createdAt: new Date(Date.now() - 725000).toISOString(),
        };
        set((state) => ({ scans: [newScan, ...state.scans] }));
      }
    }, 600);
  },

  selectScan: (scan) => set({ selectedScan: scan }),

  getComplianceReport: (framework: string) => {
    return get().complianceReports[framework] || null;
  },
}));
