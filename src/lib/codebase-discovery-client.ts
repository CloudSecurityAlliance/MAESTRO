import {
  byteLength, CODEBASE_LIMITS, validateCodebase, type PreparedCodebase,
} from './codebase';
import {
  DISCOVERY_LIMITS, validateDiscoveryInput, validateDiscoveryOutput,
  type DiscoveryInput, type DiscoveryResult, type IndexedCodebase,
} from './codebase-discovery';

export type DiscoveryRun = PreparedCodebase & { mappedFiles: number; selectionPasses: number; reasoning: string[] };

/** Two bounded planning passes. Only validated paths from the user's selection can be read. */
export async function discoverCodebase(
  entries: IndexedCodebase['entries'],
  selectFiles: (input: DiscoveryInput) => Promise<DiscoveryResult>,
  onProgress: (message: string) => void,
): Promise<DiscoveryRun> {
  const manifest = entries.map(({ path, file }) => ({ path, size: file.size }));
  const available = new Map(entries.map(entry => [entry.path, entry.file]));
  const result: DiscoveryRun = { files: [], skipped: [], mappedFiles: manifest.length, selectionPasses: 0, reasoning: [] };
  const requested = new Set<string>();
  let bytes = 0;
  for (let pass = 0; pass < 2; pass++) {
    const maxFiles = pass === 0 ? DISCOVERY_LIMITS.firstPassFiles : CODEBASE_LIMITS.files - result.files.length;
    const maxBytes = pass === 0 ? DISCOVERY_LIMITS.firstPassBytes : CODEBASE_LIMITS.totalBytes - bytes;
    if (maxFiles < 1 || maxBytes < 1) break;
    // Failed reads must not be requested repeatedly on the follow-up pass.
    const map = manifest.filter(entry => !requested.has(entry.path) || result.files.some(file => file.path === entry.path));
    const input = validateDiscoveryInput({ manifest: map, inspectedFiles: result.files, maxFiles, maxBytes });
    onProgress(pass === 0 ? 'Mapping the repository and selecting entry points…' : 'Following imports and selecting related source files…');
    const response = await selectFiles(input);
    if (!response.success) throw new Error(response.error);
    const selection = validateDiscoveryOutput(response.selection, input);
    result.selectionPasses++;
    result.reasoning.push(selection.reasoning);
    if (!selection.paths.length) break;
    onProgress(`Reading ${selection.paths.length} model-selected source files locally…`);
    for (const path of selection.paths) {
      requested.add(path);
      const file = available.get(path)!; // Membership was checked before reading any selected path.
      try {
        const content = await file.text();
        validateCodebase({ files: [{ path, content }] });
        const size = byteLength(content);
        const passLimit = pass === 0 ? DISCOVERY_LIMITS.firstPassBytes : CODEBASE_LIMITS.totalBytes;
        if (!content.trim() || bytes + size > passLimit) throw new Error('Source budget or empty file');
        result.files.push({ path, content });
        bytes += size;
      } catch {
        result.skipped.push({ path, reason: 'Unreadable, binary, empty or over-budget source file' });
      }
    }
    if (!result.files.length) throw new Error('The selected files could not be read. Try a smaller folder or manual selection.');
    if (requested.size === entries.length) break;
  }
  return result;
}
