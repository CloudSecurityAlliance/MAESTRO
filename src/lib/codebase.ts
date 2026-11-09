import { z } from 'zod';

export const CODEBASE_LIMITS = {
  files: 60,
  fileBytes: 32 * 1024,
  totalBytes: 160 * 1024,
  pathLength: 160,
} as const;

const ignoredDirectories = new Set([
  '.git', '.svn', '.hg', 'node_modules', 'vendor', '.venv', 'venv',
  'dist', 'build', 'out', 'coverage', '.next', '.nuxt', '__pycache__',
  '.aws', '.ssh', '.azure', '.terraform', '.idea', 'target', 'bin', 'obj',
]);
const sourceExtensions = new Set([
  'ts', 'tsx', 'js', 'jsx', 'mjs', 'cjs', 'py', 'go', 'rs', 'java', 'kt',
  'cs', 'rb', 'php', 'swift', 'scala', 'ex', 'exs', 'sql', 'graphql', 'gql',
  'proto', 'json', 'yaml', 'yml', 'toml', 'xml', 'tf', 'hcl', 'md', 'txt',
  'sh', 'bash', 'vue', 'svelte', 'html', 'c', 'cpp', 'h', 'hpp', 'csproj',
]);
const ignoredNames = new Set([
  'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'composer.lock',
  'cargo.lock', 'poetry.lock', 'uv.lock', 'bun.lock', 'bun.lockb',
]);

export function byteLength(text: string): number {
  return new TextEncoder().encode(text).length;
}

/** Shared by the local file picker and the server boundary. Never resolves paths on disk. */
export function fileExclusionReason(path: string): string | null {
  if (!path || path.length > CODEBASE_LIMITS.pathLength || /[\\:\x00-\x1f\x7f]/.test(path)) {
    return 'Invalid or overly long path';
  }
  const parts = path.toLowerCase().split('/');
  if (parts.some(part => !part || part === '.' || part === '..')) return 'Invalid path';
  if (parts.some(part => ignoredDirectories.has(part))) return 'Dependency, generated or private directory';
  const name = parts[parts.length - 1];
  if (parts.some(part => /^\.?env(?:[._-]|$)/.test(part) || /(?:secret|credential|token|password)/.test(part)) ||
      /^(?:id_rsa|id_ed25519|\.npmrc|\.pypirc|\.netrc|\.gitconfig)/.test(name) ||
      /\.(?:pem|key|p12|pfx|keystore|jks|crt|cer)$/.test(name)) return 'Potential secret or credential file';
  if (ignoredNames.has(name) || /(?:\.min\.[^.]+|\.map|\.lock)$/.test(name)) return 'Generated or lock file';
  if (name === 'dockerfile' || name.startsWith('dockerfile.') || name === 'makefile' || name === 'go.mod') return null;
  const extension = name.split('.').pop()!;
  return sourceExtensions.has(extension) ? null : 'Unsupported file type';
}

const SourceFileSchema = z.object({
  path: z.string().min(1).max(CODEBASE_LIMITS.pathLength),
  content: z.string().min(1).max(CODEBASE_LIMITS.fileBytes),
}).strict();

export const CodebaseInputSchema = z.object({
  files: z.array(SourceFileSchema).min(1).max(CODEBASE_LIMITS.files),
}).strict();
export type SourceFile = z.infer<typeof SourceFileSchema>;
export type CodebaseInput = z.infer<typeof CodebaseInputSchema>;

// Keep the formatted description below the existing 5,000-character form limit.
export const CodebaseOutputSchema = z.object({
  architecture: z.string().min(50).max(2200),
  evidence: z.array(z.object({
    path: z.string().min(1).max(CODEBASE_LIMITS.pathLength),
    startLine: z.number().int().min(1).max(100000),
    endLine: z.number().int().min(1).max(100000),
    observation: z.string().min(1).max(140),
  })).min(1).max(6),
  uncertainties: z.array(z.string().min(1).max(120)).min(1).max(3),
});
export type CodebaseOutput = z.infer<typeof CodebaseOutputSchema>;

export function validateCodebase(input: unknown): CodebaseInput {
  const parsed = CodebaseInputSchema.parse(input);
  const paths = new Set<string>();
  let bytes = 0;
  for (const file of parsed.files) {
    const exclusion = fileExclusionReason(file.path);
    if (exclusion) throw new Error(exclusion);
    const key = file.path.toLowerCase();
    if (paths.has(key)) throw new Error('Duplicate file path');
    paths.add(key);
    const size = byteLength(file.content);
    if (size > CODEBASE_LIMITS.fileBytes) throw new Error('File exceeds size limit');
    if (/\x00|\ufffd/.test(file.content)) throw new Error('Binary or unsupported text encoding');
    bytes += size;
  }
  if (bytes > CODEBASE_LIMITS.totalBytes) throw new Error('Source selection exceeds size limit');
  return parsed;
}

export function validateCodebaseOutput(output: unknown, files: SourceFile[]): CodebaseOutput {
  const result = CodebaseOutputSchema.parse(output);
  const sources = new Map(files.map(file => [file.path, file.content.split('\n').length]));
  for (const evidence of result.evidence) {
    const lines = sources.get(evidence.path);
    if (!lines || evidence.startLine > evidence.endLine || evidence.endLine > lines) {
      throw new Error('The model returned a source reference outside the supplied files. Please retry.');
    }
  }
  return result;
}

export function formatCodebaseArchitecture(result: CodebaseOutput, files: SourceFile[]): string {
  return [
    'Architecture inferred from selected source files (requires human review).',
    `Coverage: ${files.length} files, ${byteLength(files.map(file => file.content).join(''))} source bytes. Other files and runtime configuration were not inspected.`,
    '', result.architecture,
    '', 'Code evidence:',
    ...result.evidence.map(item => `- ${item.path}:${item.startLine}-${item.endLine}: ${item.observation}`),
    '', 'Unknowns / assumptions:',
    ...result.uncertainties.map(item => `- ${item}`),
  ].join('\n');
}

export type LocalSourceFile = {
  name: string;
  webkitRelativePath?: string;
  size: number;
  text(): Promise<string>;
};
export type PreparedCodebase = {
  files: SourceFile[];
  skipped: { path: string; reason: string }[];
};

/** Local-only preparation. No file content is sent until the user chooses extraction. */
export async function prepareCodebase(candidates: LocalSourceFile[]): Promise<PreparedCodebase> {
  const result: PreparedCodebase = { files: [], skipped: [] };
  let bytes = 0;
  const seen = new Set<string>();
  // Deterministic selection. Review the list or choose a smaller folder when limits apply.
  const ordered = candidates.map(file => ({ file, path: file.webkitRelativePath
    ? file.webkitRelativePath.split('/').slice(1).join('/') : file.name }))
    .sort((a, b) => a.path.localeCompare(b.path));
  for (const { file, path } of ordered) {
    let reason = fileExclusionReason(path);
    if (!reason && file.size > CODEBASE_LIMITS.fileBytes) reason = 'File exceeds 32 KiB';
    if (!reason && seen.has(path.toLowerCase())) reason = 'Duplicate file path';
    if (!reason && result.files.length >= CODEBASE_LIMITS.files) reason = '60-file selection limit';
    if (!reason && bytes + file.size > CODEBASE_LIMITS.totalBytes) reason = '160 KiB selection limit';
    if (reason) { result.skipped.push({ path, reason }); continue; }
    try {
      const content = await file.text();
      const size = byteLength(content);
      if (!content.trim()) reason = 'Empty file';
      else if (/\x00|\ufffd/.test(content)) reason = 'Binary or unsupported text encoding';
      else if (size > CODEBASE_LIMITS.fileBytes || bytes + size > CODEBASE_LIMITS.totalBytes) reason = 'Source size limit';
      if (reason) { result.skipped.push({ path, reason }); continue; }
      result.files.push({ path, content });
      seen.add(path.toLowerCase());
      bytes += size;
    } catch {
      result.skipped.push({ path, reason: 'Could not read file' });
    }
  }
  return result;
}
