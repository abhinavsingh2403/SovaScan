import React, { useEffect, useState } from 'react';
import { useLocation, Link } from 'react-router-dom';
import {
  Search,
  FileText,
  Zap,
  CheckCheck,
  CheckCircle2,
  Check,
  RotateCcw,
  ExternalLink,
  ChevronDown,
  FileCode,
  AlertTriangle,
  Sparkles,
  Edit3,
  Trash2,
  Copy,
  GitCommit,
  Globe,
} from 'lucide-react';
import { useStore } from '../store';
import { api } from '../api/client';
import { Finding } from '../types';
import './Findings.css';


const cleanFilePath = (path: string): string => {
  if (!path) return '';
  return path
    .replace(/\\/g, '/')
    .replace(/^(?:.*[\\/])?vulnerable-test-target[\\/]/, '')
    .replace(/^\.sovascan_cache\/clones\/[^/]+\//, '')
    .replace(/^\/app\//, '')
    .replace(/^\.\//, '');
};

const getReplacementFromPatch = (patch: string): string => {
  if (!patch) return '';
  const lines = patch.split('\n');
  const addedLines = lines
    .filter((line) => line.startsWith('+') && !line.startsWith('+++'))
    .map((line) => line.slice(1));
  return addedLines.join('\n');
};

const isLocalPath = (path: string): boolean => {
  if (!path) return false;
  const trimmed = path.trim();
  return (
    /^[a-zA-Z]:[\\/]/.test(trimmed) ||
    trimmed.startsWith('/') ||
    trimmed.startsWith('~') ||
    trimmed.startsWith('\\\\')
  );
};

function combineBaseAndCleanPath(base: string, cleanPath: string): string {
  const normBase = base.replace(/\\/g, '/').replace(/\/+$/, '');
  const normClean = cleanPath.replace(/\\/g, '/').replace(/^\/+/, '');
  const baseName = normBase.split('/').pop() || '';
  if (baseName && normClean.startsWith(`${baseName}/`)) {
    return `${normBase}/${normClean.slice(baseName.length + 1)}`;
  }
  return `${normBase}/${normClean}`;
}

export interface TargetActionResolution {
  githubUrl?: string;
  githubLabel?: string;
  vscodeUrl: string;
  cleanPath: string;
  fullPath: string;
  isAbsolute: boolean;
  isGitCommitFinding?: boolean;
}

/**
 * Resolves a finding's target file actions:
 * - For GitHub remote scans: direct URL to file or commit on GitHub
 * - For local & uploaded targets: canonical vscode://file/ URL with absolute path resolution
 */
function resolveTargetAction(
  finding: Finding,
  scans: Array<{ id: string; target: string }>,
  projectRoot: string = '',
): TargetActionResolution {
  const parentScan = scans.find((s) => s.id === finding.scanId);
  const scanTarget = (parentScan?.target ?? '').trim();
  const rawPath = finding.filePath || '';
  const cleaned = cleanFilePath(rawPath);
  const isGitHistory =
    finding.category === 'secret' &&
    (finding.ruleId?.startsWith('GIT-SECRET-') || finding.tags?.includes('git-history'));

  let githubUrl: string | undefined;
  let githubLabel: string | undefined;

  // Check if target is a Git/GitHub URL
  if (
    scanTarget.startsWith('http://') ||
    scanTarget.startsWith('https://') ||
    scanTarget.startsWith('git@')
  ) {
    if (scanTarget.includes('github.com')) {
      const repoBase = scanTarget.replace(/\.git$/, '').replace(/\/+$/, '');
      const commitHash = finding.metadata?.commit_hash;
      if (isGitHistory && commitHash) {
        githubUrl = `${repoBase}/commit/${commitHash}`;
        githubLabel = 'View Commit on GitHub ↗';
      } else {
        const lineHash = finding.lineNumber ? `#L${finding.lineNumber}` : '';
        githubUrl = `${repoBase}/blob/HEAD/${cleaned}${lineHash}`;
        githubLabel = 'Open on GitHub ↗';
      }
    }
  }

  // Determine local fullPath for VS Code opening
  const normRaw = rawPath.replace(/\\/g, '/');
  let fullPath = normRaw;
  let isAbsolute = /^[a-zA-Z]:\//i.test(normRaw) || normRaw.startsWith('/');

  if (!isAbsolute) {
    // 1. Check local roots stored in localStorage
    let storedLocalRoots: Record<string, string> = {};
    try {
      const stored = localStorage.getItem('sovascan-local-roots');
      if (stored) storedLocalRoots = JSON.parse(stored);
    } catch {
      // ignore
    }

    // Try finding a matching root
    let matchingBase = '';
    const cleanScanTarget = scanTarget.replace(/^upload:/, '').replace(/\.zip$/i, '');
    const folderNameFromTarget = cleanScanTarget.split(/[\\/]/).pop() || '';

    if (storedLocalRoots[scanTarget]) {
      matchingBase = storedLocalRoots[scanTarget];
    } else if (storedLocalRoots[cleanScanTarget]) {
      matchingBase = storedLocalRoots[cleanScanTarget];
    } else if (storedLocalRoots[folderNameFromTarget]) {
      matchingBase = storedLocalRoots[folderNameFromTarget];
    } else if (isLocalPath(scanTarget)) {
      matchingBase = scanTarget;
    } else {
      // Check stored active target path from New Scan
      try {
        const activePath = localStorage.getItem('sovascan-target-path') || '';
        if (isLocalPath(activePath)) {
          const activeFolder = activePath.replace(/[\\/]+$/, '').split(/[\\/]/).pop() || '';
          if (
            activeFolder &&
            (folderNameFromTarget === activeFolder ||
             scanTarget.includes(activeFolder) ||
             scans[0]?.id === finding.scanId)
          ) {
            matchingBase = activePath;
          }
        }
      } catch {
        // ignore
      }
    }

    // If still no matching base, try backend projectRoot if absolute
    if (!matchingBase && projectRoot && (/^[a-zA-Z]:\//i.test(projectRoot) || projectRoot.startsWith('/'))) {
      matchingBase = projectRoot;
    }

    if (matchingBase) {
      fullPath = combineBaseAndCleanPath(matchingBase, cleaned);
      isAbsolute = true;
    } else {
      fullPath = cleaned;
    }
  }

  const lineSuffix = finding.lineNumber ? `:${finding.lineNumber}` : '';
  const vscodeUrl = `vscode://file/${fullPath}${lineSuffix}`;

  return {
    githubUrl,
    githubLabel,
    vscodeUrl,
    cleanPath: cleaned,
    fullPath,
    isAbsolute,
    isGitCommitFinding: isGitHistory,
  };
}


const Findings: React.FC = () => {
  const {
    findings,
    totalFindingsCount,
    loading,
    fetchFindings,
    fixAllFindings,
    fixAllScanFindings,
    scans,
    fetchScans,
  } = useStore();
  const location = useLocation();
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [scanFilter, setScanFilter] = useState('all');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [applyingFixId, setApplyingFixId] = useState<string | null>(null);
  const [fixSuccessMsg, setFixSuccessMsg] = useState<Record<string, string>>({});
  const [applyingBulkFix, setApplyingBulkFix] = useState(false);
  const [pendingFix, setPendingFix] = useState<Record<string, { patch: string; description: string }>>({});
  const [loadingFixId, setLoadingFixId] = useState<string | null>(null);
  const [customReplacements, setCustomReplacements] = useState<Record<string, string>>({});
  const [contextCache, setContextCache] = useState<Record<string, { lines: Array<{num: number; content: string}>; targetLine: number; filePath: string; startLine: number; endLine: number }>>({});
  const [loadingContextId, setLoadingContextId] = useState<string | null>(null);
  const [collapsedContext, setCollapsedContext] = useState<Record<string, boolean>>({});
  const [currentContextText, setCurrentContextText] = useState<Record<string, string>>({});
  const [backupContextText, setBackupContextText] = useState<Record<string, string>>({});
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [projectRoot, setProjectRoot] = useState<string>('');

  useEffect(() => {
    api.getDeploymentInfo()
      .then((res: any) => {
        if (res.data?.project_root) {
          setProjectRoot(res.data.project_root);
        }
      })
      .catch(() => {});
  }, []);

  const copyToClipboard = (text: string, id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleOpenInVSCode = (finding: Finding, targetAction: TargetActionResolution) => {
    const parentScan = scans.find((s) => s.id === finding.scanId);
    const scanTarget = (parentScan?.target ?? '').trim();
    let effectiveFullPath = targetAction.fullPath;

    const isAbs = /^[a-zA-Z]:\//i.test(effectiveFullPath) || effectiveFullPath.startsWith('/');
    if (!isAbs) {
      const cleanScanTarget = scanTarget.replace(/^upload:/, '').replace(/\.zip$/i, '');
      const folderName = cleanScanTarget.split(/[\\/]/).pop() || 'project';
      const promptDefault = localStorage.getItem('sovascan-target-path') || '';
      const enteredRoot = window.prompt(
        `Enter local directory path on your computer for '${folderName}' to open in VS Code:\n(e.g. C:\\Users\\ss\\OneDrive\\Documents\\${folderName})`,
        isLocalPath(promptDefault) ? promptDefault : ''
      );

      if (!enteredRoot || !enteredRoot.trim()) {
        return;
      }

      const cleanRoot = enteredRoot.trim().replace(/[\\/]+$/, '');
      try {
        const stored = localStorage.getItem('sovascan-local-roots') || '{}';
        const roots = JSON.parse(stored);
        if (scanTarget) roots[scanTarget] = cleanRoot;
        if (cleanScanTarget) roots[cleanScanTarget] = cleanRoot;
        if (folderName) roots[folderName] = cleanRoot;
        localStorage.setItem('sovascan-local-roots', JSON.stringify(roots));
      } catch {
        // ignore
      }

      effectiveFullPath = combineBaseAndCleanPath(cleanRoot, targetAction.cleanPath);
    }

    const normPath = effectiveFullPath.replace(/\\/g, '/');
    const lineSuffix = finding.lineNumber ? `:${finding.lineNumber}` : '';
    const vscodeUri = `vscode://file/${normPath}${lineSuffix}`;

    window.location.href = vscodeUri;
  };

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const searchParam = params.get('search');
    const severityParam = params.get('severity');
    const categoryParam = params.get('category');
    const scanParam = params.get('scan');

    if (searchParam) setSearchTerm(searchParam);
    if (severityParam) setSeverityFilter(severityParam);
    if (categoryParam) setCategoryFilter(categoryParam);
    if (scanParam) setScanFilter(scanParam);
  }, [location.search]);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const scanParam = params.get('scan');
    if (!scanParam && scans.length > 0 && scanFilter === 'all') {
      const latestScan = scans[0];
      if (latestScan) {
        setScanFilter(latestScan.id);
      }
    }
  }, [scans]);


  useEffect(() => {
    fetchFindings(scanFilter === 'all' ? undefined : scanFilter);
  }, [scanFilter, fetchFindings]);

  
  const handleClearHistory = async () => {
    if (window.confirm('Purge all completed scan records and test findings from database?')) {
      try {
        await api.clearScanHistory();
        await fetchScans();
        await fetchFindings();
        setScanFilter('all');
      } catch (err: any) {
        alert('Failed to purge scan records: ' + (err?.response?.data?.detail || err?.message));
      }
    }
  };

  const handleFixAll = async () => {
    const fixableCount = findings.filter((f) => !f.isFixed).length;
    if (fixableCount === 0) {
      alert('No active findings to fix!');
      return;
    }
    const confirmMsg =
      scanFilter === 'all'
        ? `Are you sure you want to apply auto-fixes to all ${fixableCount} active findings on disk in one go?`
        : `Are you sure you want to apply auto-fixes to all ${fixableCount} active findings of the selected scan on disk in one go?`;

    if (window.confirm(confirmMsg)) {
      setApplyingBulkFix(true);
      try {
        let fixed: any[] = [];
        if (scanFilter === 'all') {
          fixed = await fixAllFindings();
        } else {
          fixed = await fixAllScanFindings(scanFilter);
        }
        if (fixed && fixed.length > 0) {
          const detailMsg = fixed
            .map((f: any) => `• ${f.title} (${f.file_path || f.filePath}:${f.line_number || f.lineNumber})`)
            .join('\n');
          alert(`Successfully applied bulk fixes to ${fixed.length} vulnerability findings:\n\n${detailMsg}`);
        } else {
          alert('Bulk fixes successfully applied to all files on disk!');
        }
      } catch (err) {
        console.error('Bulk fix failed:', err);
        alert('Failed to apply bulk fixes.');
      } finally {
        setApplyingBulkFix(false);
      }
    }
  };

  const loadFindingContext = async (finding: Finding) => {
    const id = finding.id;
    if (contextCache[id]) return;
    setLoadingContextId(id);
    try {
      const ctxRes = await api.getFindingContext(id);
      const ctxData = ctxRes.data;
      setContextCache((prev) => ({
        ...prev,
        [id]: {
          lines: ctxData.lines,
          targetLine: ctxData.target_line,
          filePath: ctxData.file_path,
          startLine: ctxData.start_line,
          endLine: ctxData.end_line,
        },
      }));

      const initialText = ctxData.lines.map((l: any) => l.content).join('\n');
      setCurrentContextText((prev) => ({
        ...prev,
        [id]: initialText,
      }));
      setBackupContextText((prev) => ({
        ...prev,
        [id]: initialText,
      }));
      let initialEvidence = finding.evidence || '';
      if (initialEvidence.trim() === 'requires login') {
        const targetLineObj = ctxData.lines.find((l: any) => l.num === finding.lineNumber);
        if (targetLineObj) {
          initialEvidence = targetLineObj.content;
        }
      }
      setCustomReplacements((prev) => ({
        ...prev,
        [id]: prev[id] !== undefined ? prev[id] : initialEvidence,
      }));
      setCollapsedContext((prev) => ({
        ...prev,
        [id]: false,
      }));
    } catch (err) {
      console.error("Failed to load context for finding", id, err);
    } finally {
      setLoadingContextId(null);
    }
  };

  const toggleExpand = async (id: string, finding: Finding) => {
    const isExpanding = expandedId !== id;
    setExpandedId(isExpanding ? id : null);
    if (isExpanding) {
      await loadFindingContext(finding);
    }
  };

  const requestFixSuggestion = async (finding: Finding, e: React.MouseEvent) => {
    e.stopPropagation();
    setExpandedId(finding.id); // auto-expand to show details/sandbox
    setLoadingFixId(finding.id);

    const fixPromise = api.applyFix(finding.id, false);
    const contextPromise = loadFindingContext(finding);

    try {
      const [res] = await Promise.all([fixPromise, contextPromise]);
      const patch = res.data?.patch || '';
      const description = res.data?.description || 'No suggestion description available.';
      
      setPendingFix((prev) => ({
        ...prev,
        [finding.id]: { patch, description },
      }));

      const replacementText = getReplacementFromPatch(patch);
      setCustomReplacements((prev) => ({
        ...prev,
        [finding.id]: replacementText,
      }));
    } catch (err: any) {
      alert(`Failed to load fix suggestion: ${err.message || err}`);
    } finally {
      setLoadingFixId(null);
    }
  };

  const confirmApplyFix = async (finding: Finding) => {
    const justification = window.prompt("Enter a justification reason for this remediation (Required for bank audits):");
    if (justification === null) {
      return; // user cancelled
    }
    const cleanJustification = justification.trim();
    if (!cleanJustification) {
      alert("Remediation Justification is mandatory for bank audits!");
      return;
    }

    setApplyingFixId(finding.id);
    try {
      const customReplacement = customReplacements[finding.id] || '';
      
      const res = await api.applyFix(
        finding.id,
        true,
        customReplacement,
        undefined, // contextReplacement
        undefined, // contextStartLine
        undefined, // contextEndLine
        cleanJustification
      );
        const desc = res.data?.description || 'Fix applied successfully!';
        setFixSuccessMsg((prev) => ({
          ...prev,
          [finding.id]: desc,
        }));
        finding.isFixed = true;

        // Refetch context to show the updated file directly on the page
        try {
          const ctxRes = await api.getFindingContext(finding.id);
          const ctxData = ctxRes.data;
          setContextCache((prev) => ({
            ...prev,
            [finding.id]: {
              lines: ctxData.lines,
              targetLine: ctxData.target_line,
              filePath: ctxData.file_path,
              startLine: ctxData.start_line,
              endLine: ctxData.end_line,
            },
          }));
          const updatedText = ctxData.lines.map((l: any) => l.content).join('\n');
          setCurrentContextText((prev) => ({
            ...prev,
            [finding.id]: updatedText,
          }));
        } catch (e) {
          console.error("Failed to refetch context", e);
        }
    } catch (err: any) {
      setFixSuccessMsg((prev) => ({
        ...prev,
        [finding.id]: `Fix request failed: ${err.message || err}`,
      }));
    } finally {
      setApplyingFixId(null);
    }
  };

  const revertAppliedFix = async (finding: Finding) => {
    const ctx = contextCache[finding.id];
    const backupText = backupContextText[finding.id];
    if (!ctx || !backupText) {
      alert("No backup context available to revert the fix!");
      return;
    }
    setApplyingFixId(finding.id);
    try {
      await api.revertFix(finding.id, backupText, ctx.startLine, ctx.endLine);
      setFixSuccessMsg((prev) => ({
        ...prev,
        [finding.id]: "Fix reverted successfully! File restored to original content.",
      }));
      finding.isFixed = false;
      
      // Refetch context to show the original content
      try {
        const ctxRes = await api.getFindingContext(finding.id);
        const ctxData = ctxRes.data;
        setContextCache((prev) => ({
          ...prev,
          [finding.id]: {
            lines: ctxData.lines,
            targetLine: ctxData.target_line,
            filePath: ctxData.file_path,
            startLine: ctxData.start_line,
            endLine: ctxData.end_line,
          },
        }));
        const restoredText = ctxData.lines.map((l: any) => l.content).join('\n');
        setCurrentContextText((prev) => ({
          ...prev,
          [finding.id]: restoredText,
        }));
        setPendingFix((prev) => {
          const next = { ...prev };
          delete next[finding.id];
          return next;
        });
      } catch (e) {
        console.error("Failed to refetch context after revert", e);
      }
    } catch (err: any) {
      alert(`Failed to revert fix: ${err.message || err}`);
    } finally {
      setApplyingFixId(null);
    }
  };

  const cancelFixSuggestion = (finding: Finding) => {
    const findingId = finding.id;
    const ctx = contextCache[findingId];
    if (ctx) {
      const originalText = ctx.lines.map((l: any) => l.content).join('\n');
      setCurrentContextText((prev) => ({
        ...prev,
        [findingId]: originalText,
      }));
    }
    let cancelEvidence = finding.evidence || '';
    if (cancelEvidence.trim() === 'requires login' && ctx) {
      const targetLineObj = ctx.lines.find((l: any) => l.num === finding.lineNumber);
      if (targetLineObj) {
        cancelEvidence = targetLineObj.content;
      }
    }
    setCustomReplacements((prev) => ({
      ...prev,
      [findingId]: cancelEvidence,
    }));
    setPendingFix((prev) => {
      const next = { ...prev };
      delete next[findingId];
      return next;
    });
    setFixSuccessMsg((prev) => {
      const next = { ...prev };
      delete next[findingId];
      return next;
    });
  };

  const renderCodeContext = (finding: Finding) => {
    const ctx = contextCache[finding.id];
    if (loadingContextId === finding.id) {
      return (
        <div className="code-context-loading">
          <div className="spinner" style={{ width: 16, height: 16 }}></div>
          <span>Loading source context...</span>
        </div>
      );
    }
    if (!ctx || !ctx.lines || ctx.lines.length === 0) return null;

    const isCollapsed = collapsedContext[finding.id] || false;

    return (
      <div className={`code-context-viewer ${finding.isFixed ? 'fixed-state' : ''}`}>
        <div 
          className="context-header" 
          onClick={() => setCollapsedContext(prev => ({ ...prev, [finding.id]: !isCollapsed }))}
          style={{ cursor: 'pointer', userSelect: 'none' }}
        >
          <span className="context-file-label" style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
            <FileCode size={14} style={{ color: 'var(--accent-primary)' }} />
            <span>{ctx.filePath}</span>
            {finding.isFixed && (
              <span className="fixed-indicator-badge" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                <CheckCheck size={11} strokeWidth={2.5} /> Applied
              </span>
            )}
          </span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="context-line-range">Lines {ctx.lines[0]?.num}–{ctx.lines[ctx.lines.length - 1]?.num}</span>
            <ChevronDown
              size={14}
              className="collapse-chevron"
              style={{
                transform: isCollapsed ? 'rotate(-90deg)' : 'rotate(0deg)',
                transition: 'transform 0.2s ease',
                display: 'inline-block',
              }}
            />
          </div>
        </div>

        {!isCollapsed && (
          <div className="context-lines-wrap" style={{ background: '#0d1117' }}>
            {ctx.lines.map((line: { num: number; content: string }) => {
              const isTarget = line.num === ctx.targetLine;
              return (
                <div
                  key={line.num}
                  className={`context-line ${isTarget ? (finding.isFixed ? 'fixed-highlight' : 'target-highlight') : ''}`}
                >
                  <span className="line-num-gutter">{line.num}</span>
                  <code className="line-content">{line.content}</code>
                </div>
              );
            })}
          </div>
        )}
      </div>
    );
  };

  const renderSideBySideSandbox = (finding: Finding) => {
    const isGitHistory =
      finding.ruleId?.startsWith('GIT-SECRET-') ||
      (finding.evidence && finding.evidence.startsWith('Commit: '));

    if (isGitHistory) {
      // Parse commit details from evidence string: "Commit: c8731e6 | Author: ... | Date: ... | Secret: ..."
      const evidence = finding.evidence || '';
      const parts: Record<string, string> = {};
      evidence.split('|').forEach((seg) => {
        const idx = seg.indexOf(':');
        if (idx !== -1) {
          const k = seg.slice(0, idx).trim().toLowerCase();
          const v = seg.slice(idx + 1).trim();
          parts[k] = v;
        }
      });
      const commitHash = parts['commit'] || finding.metadata?.commit_short || 'HEAD';
      const commitAuthor = parts['author'] || finding.metadata?.commit_author || 'Git Contributor';
      const commitDate = parts['date'] || finding.metadata?.commit_date || '';
      const maskedSecret = parts['secret'] || finding.metadata?.masked_value || '••••••••';
      
      const parentScan = scans.find((s) => s.id === finding.scanId);
      const isGitHub = (parentScan?.target || '').includes('github.com');
      const repoBase = (parentScan?.target || '').replace(/\.git$/, '').replace(/\/+$/, '');
      const commitUrl = isGitHub && commitHash ? `${repoBase}/commit/${commitHash}` : null;
      const purgeCmd = `git filter-repo --invert-paths --path "${cleanFilePath(finding.filePath)}"`;

      return (
        <div className="git-leak-sandbox glassmorphism" style={{
          marginTop: '16px',
          marginBottom: '12px',
          padding: '16px 20px',
          borderRadius: '10px',
          background: 'rgba(244, 63, 94, 0.04)',
          border: '1px solid rgba(244, 63, 94, 0.25)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', color: '#f43f5e', fontWeight: 600, fontSize: '13px' }}>
              <GitCommit size={15} /> Leaked Credential in Past Git Commit
            </span>
            {commitUrl && (
              <a
                href={commitUrl}
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  color: 'var(--accent-telemetry, #06b6d4)',
                  fontSize: '12px',
                  textDecoration: 'none',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '4px',
                  fontWeight: 500,
                }}
              >
                <ExternalLink size={12} /> View Commit on GitHub ↗
              </a>
            )}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '10px', marginBottom: '14px' }}>
            <div style={{ background: 'rgba(0,0,0,0.3)', padding: '8px 12px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.06)' }}>
              <div style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-secondary)', letterSpacing: '0.5px' }}>Commit SHA</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: '#f3f4f6', marginTop: '2px', fontWeight: 600 }}>{commitHash}</div>
            </div>
            <div style={{ background: 'rgba(0,0,0,0.3)', padding: '8px 12px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.06)' }}>
              <div style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-secondary)', letterSpacing: '0.5px' }}>Author</div>
              <div style={{ fontSize: '12px', color: '#f3f4f6', marginTop: '2px' }}>{commitAuthor}</div>
            </div>
            {commitDate && (
              <div style={{ background: 'rgba(0,0,0,0.3)', padding: '8px 12px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.06)' }}>
                <div style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-secondary)', letterSpacing: '0.5px' }}>Committed At</div>
                <div style={{ fontSize: '12px', color: '#f3f4f6', marginTop: '2px' }}>{commitDate}</div>
              </div>
            )}
            <div style={{ background: 'rgba(0,0,0,0.3)', padding: '8px 12px', borderRadius: '6px', border: '1px solid rgba(244, 63, 94, 0.2)' }}>
              <div style={{ fontSize: '10px', textTransform: 'uppercase', color: '#f43f5e', letterSpacing: '0.5px' }}>Secret Value (Masked)</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: '#f43f5e', marginTop: '2px', fontWeight: 600 }}>{maskedSecret}</div>
            </div>
          </div>

          <div style={{ background: 'rgba(0,0,0,0.4)', borderRadius: '6px', padding: '10px 14px', border: '1px solid rgba(255,255,255,0.08)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-secondary)', fontWeight: 600 }}>Permanent Purge Command (git filter-repo):</span>
              <button
                type="button"
                onClick={(e) => copyToClipboard(purgeCmd, `purge-${finding.id}`, e)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: 'var(--accent-primary)',
                  fontSize: '11px',
                  cursor: 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '4px',
                  padding: '2px 6px',
                }}
              >
                {copiedId === `purge-${finding.id}` ? <Check size={11} /> : <Copy size={11} />}
                {copiedId === `purge-${finding.id}` ? 'Copied' : 'Copy Command'}
              </button>
            </div>
            <code style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: '#38bdf8', wordBreak: 'break-all', display: 'block' }}>
              {purgeCmd}
            </code>
          </div>
        </div>
      );
    }

    let originalCode = finding.evidence || '';
    if (originalCode.trim() === 'requires login' && contextCache[finding.id]) {
      const targetLineObj = contextCache[finding.id].lines.find((l: any) => l.num === finding.lineNumber);
      if (targetLineObj) {
        originalCode = targetLineObj.content;
      }
    }
    const currentValue = customReplacements[finding.id] !== undefined ? customReplacements[finding.id] : '';

    return (
      <div className="split-diff-container" style={{ marginTop: '16px', marginBottom: '12px' }}>
        {/* Left Pane: Original Code */}
        <div className="split-pane original-pane" style={{ background: 'rgba(0, 0, 0, 0.25)' }}>
          <div className="pane-header header-original" style={{ background: 'rgba(239, 68, 68, 0.08)', color: '#FF003C', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span className="pane-indicator" style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
              <AlertTriangle size={13} strokeWidth={2} /> Original Code
            </span>
            <span className="file-tag">Original</span>
          </div>
          <div className="pane-editor-wrap" style={{ padding: '12px', background: 'rgba(0, 0, 0, 0.15)' }}>
            <pre className="code-display" style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: '#FF003C' }}>
              <code>{originalCode}</code>
            </pre>
          </div>
        </div>

        {/* Right Pane: Proposed Sandbox Editor */}
        <div className="split-pane sandbox-pane" style={{ background: 'rgba(0, 0, 0, 0.25)' }}>
          <div className="pane-header header-sandbox" style={{ background: 'rgba(16, 185, 129, 0.08)', color: '#34d399', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span className="pane-indicator" style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
              <Sparkles size={13} strokeWidth={2} /> Sandbox / Proposed Fix
            </span>
            <span className="edit-badge" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
              Editable <Edit3 size={11} strokeWidth={2} />
            </span>
          </div>
          <div className="pane-editor-wrap" style={{ padding: '12px', background: 'rgba(0, 0, 0, 0.15)' }}>
            <textarea
              className="sandbox-textarea"
              value={currentValue}
              disabled={finding.isFixed}
              onChange={(e) => {
                setCustomReplacements((prev) => ({
                  ...prev,
                  [finding.id]: e.target.value,
                }));
              }}
              placeholder="// Write/tweak your replacement code here..."
              rows={Math.max(3, currentValue.split('\n').length)}
              style={{
                width: '100%',
                background: 'transparent',
                color: '#34d399',
                border: 'none',
                fontFamily: "'Fira Code', 'Courier New', Courier, monospace",
                fontSize: '12px',
                lineHeight: '1.5',
                resize: 'vertical',
                outline: 'none',
                padding: 0,
                margin: 0,
                whiteSpace: 'pre',
                tabSize: 4,
              }}
            />
          </div>
        </div>
      </div>
    );
  };

  const getVulnerabilityImpact = (finding: Finding) => {
    const category = (finding.category || '').toLowerCase();
    const ruleId = (finding.ruleId || '').toUpperCase();
    const title = (finding.title || '').toLowerCase();

    if (category === 'secret') {
      return (
        "An attacker can steal this hardcoded credential and gain direct access to your databases, " +
        "cloud services, external APIs, or communication channels. This can lead to massive data theft, " +
        "service abuse, or severe financial losses."
      );
    }
    
    if (category === 'cve') {
      const cveName = finding.cveId || 'a third-party library';
      return (
        `Using ${cveName} with known public vulnerabilities means attackers can exploit well-documented bugs. ` +
        "Depending on the specific bug, they could crash your server, steal data, or run malicious code on your systems."
      );
    }

    if (ruleId === 'SOVA-INFRA-001' || title.includes('root user')) {
      return (
        "Running your application containers as 'root' (admin) means if an attacker compromises the app, " +
        "they instantly gain admin control over the container. This makes it significantly easier to break out " +
        "and compromise the host server."
      );
    }

    if (ruleId === 'SOVA-MISCONFIG-001' || title.includes('debug mode') || title.includes('debug')) {
      return (
        "Enabling debug mode in production exposes internal code stack traces, server path details, and environment variables " +
        "to the public whenever an error occurs. Attackers use this blueprint to locate further entry points."
      );
    }

    if (ruleId === 'SOVA-INFRA-002' || title.includes('base image')) {
      return (
        "Using unpinned, outdated, or generic base images introduces pre-existing vulnerabilities into your container environment " +
        "and makes your builds unpredictable, increasing the risk of code breaking unexpectedly."
      );
    }

    if (ruleId.startsWith('SOVA-WEB-') || title.includes('headers') || title.includes('ssl') || title.includes('tls')) {
      return (
        "Missing HTTP security headers or weak SSL/TLS settings leave your users vulnerable to browser-based attacks " +
        "such as clickjacking, cross-site scripting (XSS), or having their traffic intercepted (man-in-the-middle)."
      );
    }

    if (ruleId.startsWith('SOVA-DB-') || title.includes('database') || title.includes('sql')) {
      return (
        "Weak database configurations (such as empty passwords or allowing connections from any IP) let attackers " +
        "brute-force or connect directly to your database, exposing all stored sensitive data to theft or deletion."
      );
    }

    if (category === 'config_drift') {
      return (
        "Unauthorized settings changes or drift from your approved security baseline mean that security controls " +
        "might have been disabled or altered, leaving unknown configuration gaps or causing system instability."
      );
    }

    // Default fallback
    return (
      "This misconfiguration weakens the defensive layers of your application. It could allow unauthorized users " +
      "to bypass security controls, view internal system data, or trigger service disruptions."
    );
  };

  // Extract unique categories for filter
  const categories = ['all', ...Array.from(new Set(findings.map((f) => f.category)))];

  // Filtering logic
  const filteredFindings = findings.filter((f) => {
    const matchesSearch =
      f.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.filePath.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.ruleId.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesSeverity = severityFilter === 'all' || f.severity === severityFilter;
    const matchesCategory = categoryFilter === 'all' || f.category === categoryFilter;
    const matchesScan = scanFilter === 'all' || f.scanId === scanFilter;

    return matchesSearch && matchesSeverity && matchesCategory && matchesScan;
  });

  return (
    <div className="findings-container">
      {/* Filters Bar */}
      <div className="filters-bar glassmorphism animate-fade-in">
        <div className="search-box">
          <span className="search-icon">
            <Search size={15} strokeWidth={2} />
          </span>
          <input
            type="text"
            placeholder="Search by title, file path, rule ID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>

        <div className="dropdowns-wrap">
          <div className="filter-select">
            <label>Scan:</label>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center', width: '100%' }}>
              <select
                value={scanFilter}
                onChange={(e) => setScanFilter(e.target.value)}
                style={{ flex: 1 }}
              >
                <option value="all">All Scans</option>
                {scans.map((scan) => (
                  <option key={scan.id} value={scan.id}>
                    {scan.target} ({new Date(scan.createdAt).toLocaleDateString()})
                  </option>
                ))}
              </select>
              {scanFilter !== 'all' && (
                <Link
                  to={`/report/${scanFilter}`}
                  className="settings__btn settings__btn--secondary"
                  style={{
                    textDecoration: 'none',
                    display: 'inline-flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '11px',
                    padding: '8px 12px',
                    height: '35px',
                    boxSizing: 'border-box',
                    whiteSpace: 'nowrap',
                    gap: '5px',
                  }}
                  title="View Scan Report"
                >
                  <FileText size={13} strokeWidth={1.8} /> Report
                </Link>
              )}
            </div>
          </div>

          <div className="filter-select">
            <label>Severity:</label>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>

          <div className="filter-select">
            <label>Category:</label>
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
            >
              {categories.map((cat) => (
                <option key={cat} value={cat}>
                  {cat === 'all' ? 'All Categories' : cat}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Findings Count Summary */}
      <div className="results-summary animate-fade-in">
        <p>
          Showing <span>{filteredFindings.length}</span> of <span>{totalFindingsCount > 0 ? totalFindingsCount : findings.length}</span> active
          findings
        </p>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <button
            type="button"
            className="settings__btn settings__btn--secondary"
            onClick={handleClearHistory}
            style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', fontSize: '12px', padding: '6px 12px', height: '35px' }}
            title="Purge all completed and test scan history from database"
          >
            <Trash2 size={13} /> Purge Test Records
          </button>
          {findings.some((f) => !f.isFixed) && (
            <button
              className="fix-all-btn"
              onClick={handleFixAll}
              disabled={applyingBulkFix}
              style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
            >
              <Zap size={13} strokeWidth={2.2} />
              {applyingBulkFix ? 'Applying Bulk Fixes...' : 'Fix All (1-Go)'}
            </button>
          )}
        </div>
      </div>

      {/* Findings Table/Accordion List */}
      <div className="findings-list animate-slide-up stagger-children">
        {loading ? (
          <div className="findings-loading">
            <div className="spinner"></div>
            <p>Analyzing vulnerabilities...</p>
          </div>
        ) : filteredFindings.length === 0 ? (
          <div className="no-findings glassmorphism">
            <h3>No matching findings found</h3>
            <p>Try resetting your filters or start a new scan.</p>
          </div>
        ) : (
          filteredFindings.map((finding) => {
            const isExpanded = expandedId === finding.id;
            return (
              <div
                key={finding.id}
                className={`finding-row-card glassmorphism ${isExpanded ? 'expanded' : ''} ${
                  finding.isFixed ? 'fixed' : ''
                }`}
                onClick={() => toggleExpand(finding.id, finding)}
              >
                {/* Header Summary Row */}
                <div className="finding-header">
                  <div className="left-meta">
                    <span className={`severity-badge-lbl ${finding.severity}`}>
                      {finding.severity}
                    </span>
                    <span className="rule-id-lbl">{finding.ruleId}</span>
                  </div>
                  <div className="finding-title-sec">
                    <h4>{finding.title}</h4>
                    <p className="path-text">{cleanFilePath(finding.filePath)}:{finding.lineNumber}</p>
                  </div>
                  <div className="right-controls">
                    <span className="category-tag">{finding.category}</span>
                    {finding.cvssScore && (
                      <span className="cvss-badge">CVSS {finding.cvssScore}</span>
                    )}
                    {finding.isFixed ? (
                      <span className="fixed-pill" style={{ display: 'inline-flex', alignItems: 'center', gap: '5px' }}>
                        <CheckCheck size={12} strokeWidth={2.2} /> Fixed
                      </span>
                    ) : (
                      <button
                        className="auto-fix-btn"
                        onClick={(e) => requestFixSuggestion(finding, e)}
                        disabled={loadingFixId === finding.id || applyingFixId === finding.id}
                        style={{ display: 'inline-flex', alignItems: 'center', gap: '5px' }}
                      >
                        <Zap size={12} strokeWidth={2.2} />
                        {loadingFixId === finding.id ? 'Loading...' : 'Auto Fix'}
                      </button>
                    )}
                    <ChevronDown
                      size={15}
                      className={`chevron ${isExpanded ? 'up' : 'down'}`}
                      style={{
                        transform: isExpanded ? 'rotate(180deg)' : 'rotate(0deg)',
                        transition: 'transform 0.2s ease',
                      }}
                    />
                  </div>
                </div>

                {/* Expanded Details Body */}
                <div className={`finding-body smooth-expand ${isExpanded ? 'show' : ''}`} onClick={(e) => e.stopPropagation()}>
                  <div className="details-section">
                    <h5>Description</h5>
                    <p className="desc-text">{finding.description}</p>
                  </div>

                  <div className="details-section">
                    <h5>Potential Impact (Plain English)</h5>
                    <p className="impact-text">{getVulnerabilityImpact(finding)}</p>
                  </div>

                  <div className="details-section">
                    <h5>Code Context Sandbox</h5>
                    <p className="sandbox-help-text" style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '8px' }}>
                      Edit the code directly inside the sandbox box below, or click <strong>⚡ Auto Fix</strong> to view the AI suggestion.
                    </p>
                    
                    {renderCodeContext(finding)}
                    {!finding.isFixed && renderSideBySideSandbox(finding)}

                    {!finding.isFixed && pendingFix[finding.id] && (
                      <div className="fix-desc-box" style={{ 
                        marginTop: '8px', 
                        marginBottom: '8px', 
                        padding: '10px 12px', 
                        background: 'rgba(245, 158, 11, 0.08)', 
                        borderLeft: '3px solid #f59e0b',
                        borderRadius: '4px', 
                        fontSize: '12px',
                        color: '#f3f4f6'
                      }}>
                        <strong>AI Fix Suggestion:</strong> {pendingFix[finding.id].description}
                      </div>
                    )}
                    
                    <div className="fix-actions" style={{ marginTop: '12px', marginBottom: '16px', display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center' }}>
                      {(() => {
                        const targetAction = resolveTargetAction(finding, scans, projectRoot);
                        return (
                          <>
                            {targetAction.githubUrl && (
                              <a
                                className="editor-link-btn"
                                href={targetAction.githubUrl}
                                target="_blank"
                                rel="noopener noreferrer"
                                onClick={(e) => e.stopPropagation()}
                                style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
                              >
                                <Globe size={13} strokeWidth={2} /> {targetAction.githubLabel || 'Open on GitHub ↗'}
                              </a>
                            )}

                            <button
                              type="button"
                              className="editor-link-btn"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleOpenInVSCode(finding, targetAction);
                              }}
                              style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '6px',
                                background: 'rgba(99, 102, 241, 0.12)',
                                border: '1px solid rgba(99, 102, 241, 0.35)',
                                color: 'var(--text-primary)',
                                cursor: 'pointer',
                              }}
                              title={
                                targetAction.isAbsolute
                                  ? `Open in VS Code: ${targetAction.fullPath}`
                                  : 'Open in VS Code'
                              }
                            >
                              <ExternalLink size={13} strokeWidth={2} /> Open in VS Code
                            </button>
                          </>
                        );
                      })()}


                      <button
                        type="button"
                        className="settings__btn settings__btn--secondary"
                        onClick={(e) => copyToClipboard(cleanFilePath(finding.filePath), `path-${finding.id}`, e)}
                        style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', fontSize: '12px', padding: '6px 12px', height: '32px' }}
                        title="Copy relative file path to clipboard"
                      >
                        {copiedId === `path-${finding.id}` ? (
                          <>
                            <Check size={13} style={{ color: '#10b981' }} /> Copied!
                          </>
                        ) : (
                          <>
                            <Copy size={13} /> Copy Path
                          </>
                        )}
                      </button>

                      {finding.isFixed ? (
                        <>
                          <button
                            className="confirm-fix-btn success-applied"
                            disabled={true}
                            style={{ marginRight: '8px', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
                          >
                            <CheckCircle2 size={13} strokeWidth={2.2} /> Applied to Disk
                          </button>
                          <button
                            className="revert-fix-btn"
                            onClick={() => revertAppliedFix(finding)}
                            disabled={applyingFixId === finding.id}
                            style={{
                              background: 'rgba(255, 255, 255, 0.08)',
                              border: '1px solid rgba(255, 255, 255, 0.15)',
                              color: '#c9d1d9',
                              padding: '8px 16px',
                              borderRadius: '6px',
                              fontWeight: '600',
                              cursor: 'pointer',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '6px',
                            }}
                          >
                            <RotateCcw size={13} strokeWidth={2} />
                            {applyingFixId === finding.id ? 'Reverting...' : 'Revert Fix'}
                          </button>
                        </>
                      ) : (
                        <>
                          <button
                            className="confirm-fix-btn"
                            onClick={() => confirmApplyFix(finding)}
                            disabled={applyingFixId === finding.id || loadingContextId === finding.id}
                            style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
                          >
                            <Check size={13} strokeWidth={2.2} />
                            {applyingFixId === finding.id ? 'Applying to disk...' : 'Confirm & Apply Fix'}
                          </button>
                          
                          <button
                            className="cancel-fix-btn"
                            onClick={() => cancelFixSuggestion(finding)}
                          >
                            Reset
                          </button>
                        </>
                      )}
                    </div>

                    {finding.isFixed && (
                      <div className="fix-applied-desc-banner" style={{
                        marginTop: '12px',
                        padding: '12px 16px',
                        background: 'rgba(16, 185, 129, 0.08)',
                        border: '1px solid rgba(16, 185, 129, 0.25)',
                        borderRadius: '6px',
                        color: '#34d399',
                        fontSize: '12px',
                        lineHeight: '1.5'
                      }}>
                        {pendingFix[finding.id]?.description || finding.description}
                      </div>
                    )}
                  </div>

                  <div className="details-section">
                    <h5>Remediation Steps</h5>
                    <p className="remediation-text">{finding.remediation}</p>
                  </div>

                  {finding.cveId && (
                    <div className="details-section">
                      <h5>Vulnerability Identifier</h5>
                      <p className="cve-link-text">
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${finding.cveId}`}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          {finding.cveId} (NVD details)
                        </a>
                      </p>
                    </div>
                  )}

                  {fixSuccessMsg[finding.id] && (
                    <div className="fix-success-banner">
                      {fixSuccessMsg[finding.id]}
                    </div>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};

export default Findings;
