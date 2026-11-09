import { z } from 'zod';
import {
  byteLength, CODEBASE_LIMITS, CodebaseInputSchema, fileExclusionReason,
  validateCodebase, type LocalSourceFile,
} from './codebase';

export const DISCOVERY_LIMITS = {
  mapFiles: 2000,
  mapBytes: 192 * 1024,
  firstPassFiles: 30,
  firstPassBytes: 80 * 1024,
} as const;

const FileMapEntrySchema = z.object({
  path: z.string().min(1).max(CODEBASE_LIMITS.pathLength),
  size: z.number().int().min(1).max(CODEBASE_LIMITS.fileBytes),
}).strict();

export const DiscoveryInputSchema = z.object({
  manifest: z.array(FileMapEntrySchema).min(1).max(DISCOVERY_LIMITS.mapFiles),
  inspectedFiles: z.array(CodebaseInputSchema.shape.files.element).max(CODEBASE_LIMITS.files),
  maxFiles: z.number().int().min(1).max(CODEBASE_LIMITS.files),
  maxBytes: z.number().int().min(1).max(CODEBASE_LIMITS.totalBytes),
}).strict();
export type DiscoveryInput = z.infer<typeof DiscoveryInputSchema>;

export const DiscoveryOutputSchema = z.object({
  paths: z.array(z.string().min(1).max(CODEBASE_LIMITS.pathLength)).max(CODEBASE_LIMITS.files),
  reasoning: z.string().min(1).max(500),
});
export type DiscoveryOutput = z.infer<typeof DiscoveryOutputSchema>;
export type DiscoveryResult = { success: true; selection: DiscoveryOutput } | { success: false; error: string };

export function validateDiscoveryInput(input: unknown): DiscoveryInput {
  const parsed = DiscoveryInputSchema.parse(input);
  if (byteLength(JSON.stringify(parsed.manifest)) > DISCOVERY_LIMITS.mapBytes) throw new Error('Repository map exceeds byte limit');
  const paths = new Map<string, number>();
  const unique = new Set<string>();
  for (const entry of parsed.manifest) {
    if (fileExclusionReason(entry.path) || unique.has(entry.path.toLowerCase())) throw new Error('Invalid repository map');
    paths.set(entry.path, entry.size);
    unique.add(entry.path.toLowerCase());
  }
  if (parsed.inspectedFiles.length) validateCodebase({ files: parsed.inspectedFiles });
  let inspectedBytes = 0;
  for (const file of parsed.inspectedFiles) {
    if (!paths.has(file.path)) throw new Error('Inspected source is outside the repository map');
    inspectedBytes += byteLength(file.content);
  }
  // Bound map + inspected source together below the default server-action request limit.
  if (inspectedBytes > DISCOVERY_LIMITS.firstPassBytes) throw new Error('Discovery source context exceeds limit');
  if (parsed.inspectedFiles.length + parsed.maxFiles > CODEBASE_LIMITS.files ||
      inspectedBytes + parsed.maxBytes > CODEBASE_LIMITS.totalBytes) throw new Error('Invalid remaining source budget');
  return parsed;
}

/** Validate model-selected paths before any client reads or sends those files. */
export function validateDiscoveryOutput(output: unknown, input: DiscoveryInput): DiscoveryOutput {
  const result = DiscoveryOutputSchema.parse(output);
  const available = new Map(input.manifest.map(file => [file.path, file.size]));
  const alreadyRead = new Set(input.inspectedFiles.map(file => file.path));
  const selected = new Set<string>();
  let bytes = 0;
  if (result.paths.length > input.maxFiles) throw new Error('Model selected too many files');
  for (const path of result.paths) {
    const size = available.get(path);
    if (size === undefined || alreadyRead.has(path) || selected.has(path)) throw new Error('Model selected an invalid source path');
    selected.add(path);
    bytes += size;
  }
  if (bytes > input.maxBytes) throw new Error('Model selection exceeds source budget');
  if (!input.inspectedFiles.length && !result.paths.length) throw new Error('Model did not select any source files');
  return result;
}

export type IndexedCodebase = {
  entries: { path: string; file: LocalSourceFile }[];
  skipped: { path: string; reason: string }[];
};

function mapPriority(path: string): number {
  // Only used when the map exceeds its limit. Actual source selection belongs to the model.
  if (/(?:^|\/)(?:readme\.md|package\.json|pyproject\.toml|go\.mod|cargo\.toml|dockerfile)$/i.test(path)) return 0;
  if (/(?:^|\/)(?:main|app|server|index)\.[^.]+$/i.test(path)) return 1;
  if (/(?:auth|middleware|routes|agent|tools|config|deploy|infra)/i.test(path)) return 2;
  return 3;
}

/** Build a metadata-only map. No file content is read or transmitted here. */
export function indexCodebase(candidates: LocalSourceFile[]): IndexedCodebase {
  const result: IndexedCodebase = { entries: [], skipped: [] };
  const seen = new Set<string>();
  let mapBytes = 2; // JSON array brackets
  const ordered = candidates.map(file => ({ file, path: file.webkitRelativePath
    ? file.webkitRelativePath.split('/').slice(1).join('/') : file.name }))
    .sort((a, b) => mapPriority(a.path) - mapPriority(b.path) || a.path.localeCompare(b.path));
  for (const entry of ordered) {
    const { path, file } = entry;
    const entryBytes = byteLength(JSON.stringify({ path, size: file.size })) + (result.entries.length ? 1 : 0);
    let reason = fileExclusionReason(path);
    if (!reason && (file.size <= 0 || !Number.isSafeInteger(file.size))) reason = 'Empty file or invalid size';
    if (!reason && file.size > CODEBASE_LIMITS.fileBytes) reason = 'File exceeds 32 KiB';
    if (!reason && seen.has(path.toLowerCase())) reason = 'Duplicate file path';
    if (!reason && (result.entries.length >= DISCOVERY_LIMITS.mapFiles || mapBytes + entryBytes > DISCOVERY_LIMITS.mapBytes)) reason = 'Repository map limit; choose a smaller subsystem for additional coverage';
    if (reason) { result.skipped.push({ path, reason }); continue; }
    result.entries.push(entry);
    seen.add(path.toLowerCase());
    mapBytes += entryBytes;
  }
  return result;
}
