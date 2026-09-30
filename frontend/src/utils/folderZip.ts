/**
 * Utility to package client-selected directory files into a clean ZIP archive in-browser
 * before uploading to SovaScan server for scanning.
 * Automatically excludes noisy vendor/temp directories (node_modules, .git, venv, etc.).
 */
import JSZip from 'jszip';

const IGNORED_DIRS = new Set([
  'node_modules',
  '.git',
  '.venv',
  'venv',
  'env',
  '__pycache__',
  'dist',
  'build',
  '.next',
  '.nuxt',
  '.cache',
  '.sovascan_cache',
  '.pytest_cache',
  '.idea',
  '.vscode',
]);

const IGNORED_EXTS = new Set([
  '.exe',
  '.dll',
  '.so',
  '.dylib',
  '.bin',
  '.iso',
  '.dmg',
  '.zip',
  '.tar',
  '.gz',
  '.rar',
  '.7z',
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.mp4',
  '.mp3',
  '.wav',
  '.mov',
  '.avi',
  '.woff',
  '.woff2',
  '.ttf',
  '.eot',
  '.pyc',
  '.pyo',
]);

export interface ZipFolderResult {
  blob: Blob;
  filename: string;
  folderName: string;
  totalFiles: number;
  uncompressedSize: number;
}

export async function zipFolderFiles(
  files: FileList | File[],
  onProgress?: (percent: number, status: string) => void
): Promise<ZipFolderResult> {
  const zip = new JSZip();
  const fileArray = Array.from(files);

  if (fileArray.length === 0) {
    throw new Error('No files found in selected folder.');
  }

  // Determine root folder name from webkitRelativePath
  let rootFolderName = 'project';
  const firstPath = (fileArray[0] as any).webkitRelativePath || fileArray[0].name;
  if (firstPath.includes('/')) {
    rootFolderName = firstPath.split('/')[0];
  } else if (fileArray[0].name) {
    rootFolderName = fileArray[0].name.replace(/\.[^/.]+$/, '');
  }

  let includedCount = 0;
  let totalBytes = 0;

  for (let i = 0; i < fileArray.length; i++) {
    const file = fileArray[i];
    const relPath: string = (file as any).webkitRelativePath || file.name;

    // Check if any segment is an ignored directory
    const parts = relPath.replace(/\\/g, '/').split('/');
    const isIgnoredDir = parts.some((p: string) => IGNORED_DIRS.has(p));
    const ext = '.' + file.name.split('.').pop()?.toLowerCase();
    const isIgnoredExt = IGNORED_EXTS.has(ext);

    // Skip ignored directories, binaries, and giant single files (> 15MB)
    if (isIgnoredDir || isIgnoredExt || file.size > 15 * 1024 * 1024) {
      continue;
    }

    // Strip top root folder name from relative path so inside zip it starts at root
    const cleanRelPath = parts.length > 1 ? parts.slice(1).join('/') : relPath;
    if (!cleanRelPath) continue;

    zip.file(cleanRelPath, file);
    includedCount++;
    totalBytes += file.size;

    if (onProgress && i % 25 === 0) {
      const pct = Math.round((i / fileArray.length) * 40);
      onProgress(pct, `Reading ${file.name}...`);
    }
  }

  if (includedCount === 0) {
    throw new Error(
      `No scannable code files found in folder '${rootFolderName}'. Make sure it contains supported source or manifest files.`
    );
  }

  if (onProgress) {
    onProgress(50, `Archiving ${includedCount} files...`);
  }

  const blob = await zip.generateAsync(
    {
      type: 'blob',
      compression: 'DEFLATE',
      compressionOptions: { level: 6 },
    },
    (metadata) => {
      if (onProgress) {
        onProgress(50 + Math.round(metadata.percent * 0.45), 'Compressing files...');
      }
    }
  );

  return {
    blob,
    filename: `${rootFolderName}.zip`,
    folderName: rootFolderName,
    totalFiles: includedCount,
    uncompressedSize: totalBytes,
  };
}

/**
 * Prompts the user with native local system permission dialog (File System Access API)
 * to select a directory on their machine and package it for security scanning.
 */
export async function pickAndZipDirectoryWithPermission(
  onProgress?: (percent: number, status: string) => void
): Promise<ZipFolderResult> {
  if (typeof window !== 'undefined' && 'showDirectoryPicker' in window) {
    try {
      // Requests native OS / browser permission from user to access the local folder
      const dirHandle = await (window as any).showDirectoryPicker({
        mode: 'read',
      });

      const zip = new JSZip();
      const folderName = dirHandle.name || 'project';
      let totalFiles = 0;
      let totalBytes = 0;

      onProgress?.(10, `Local system permission granted for '${folderName}'. Scanning directory tree...`);

      async function readDirectory(handle: any, currentPath: string) {
        for await (const entry of handle.values()) {
          const entryPath = currentPath ? `${currentPath}/${entry.name}` : entry.name;
          if (entry.kind === 'directory') {
            if (IGNORED_DIRS.has(entry.name)) continue;
            await readDirectory(entry, entryPath);
          } else if (entry.kind === 'file') {
            const ext = '.' + entry.name.split('.').pop()?.toLowerCase();
            if (IGNORED_EXTS.has(ext)) continue;

            const file = await entry.getFile();
            if (file.size > 15 * 1024 * 1024) continue; // skip oversized files

            const arrayBuf = await file.arrayBuffer();
            zip.file(entryPath, arrayBuf);
            totalFiles++;
            totalBytes += file.size;

            if (onProgress && totalFiles % 10 === 0) {
              onProgress(
                20,
                `Authorized by system: indexed ${totalFiles} files (${(totalBytes / 1024).toFixed(0)} KB)...`
              );
            }
          }
        }
      }

      await readDirectory(dirHandle, '');

      if (totalFiles === 0) {
        throw new Error('No scannable code files found in selected folder.');
      }

      onProgress?.(60, `Packaging ${totalFiles} files for analysis...`);

      const blob = await zip.generateAsync(
        {
          type: 'blob',
          compression: 'DEFLATE',
          compressionOptions: { level: 6 },
        },
        (meta) => {
          onProgress?.(
            60 + Math.round(meta.percent * 0.38),
            `Finalizing package: ${Math.round(meta.percent)}%`
          );
        }
      );

      return {
        blob,
        filename: `${folderName}.zip`,
        folderName,
        totalFiles,
        uncompressedSize: totalBytes,
      };
    } catch (err: any) {
      if (err.name === 'AbortError') {
        throw new Error('Directory selection was cancelled.');
      }
      throw err;
    }
  }

  throw new Error('showDirectoryPicker not supported');
}

