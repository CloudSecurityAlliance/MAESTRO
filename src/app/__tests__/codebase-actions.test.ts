import { beforeEach, describe, expect, it, vi } from 'vitest';
import { extractArchitectureFromCodebase, selectFilesForArchitecture } from '../codebase-actions';
import { extractCodebaseArchitecture } from '@/ai/flows/extract-codebase-architecture';
import { selectRelevantCodebaseFiles } from '@/ai/flows/select-codebase-files';

vi.mock('@/ai/flows/extract-codebase-architecture', () => ({ extractCodebaseArchitecture: vi.fn() }));
vi.mock('@/ai/flows/select-codebase-files', () => ({ selectRelevantCodebaseFiles: vi.fn() }));

describe('codebase extraction action', () => {
  beforeEach(() => vi.resetAllMocks());

  it('rejects bypassed client restrictions before invoking the provider', async () => {
    const result = await extractArchitectureFromCodebase({ files: [{ path: '.env', content: 'KEY=secret' }] });
    expect(result.success).toBe(false);
    expect(extractCodebaseArchitecture).not.toHaveBeenCalled();
  });

  it('returns architecture, evidence and coverage for the existing analysis', async () => {
    vi.mocked(extractCodebaseArchitecture).mockResolvedValue({
      architecture: 'An HTTP service reads data through a database client. Authentication is not visible in this selection.',
      evidence: [{ path: 'api.ts', startLine: 1, endLine: 1, observation: 'Reads data.' }],
      uncertainties: ['Runtime permissions are unknown.'],
    });
    const result = await extractArchitectureFromCodebase({ files: [{ path: 'api.ts', content: 'db.read()' }] });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.architectureDescription).toContain('api.ts:1-1');
      expect(result.architectureDescription).toContain('Runtime permissions are unknown.');
    }
  });

  it('does not expose source fragments from provider failures', async () => {
    vi.mocked(extractCodebaseArchitecture).mockRejectedValue(new Error('Provider failed with private-source-fragment'));
    const result = await extractArchitectureFromCodebase({ files: [{ path: 'api.ts', content: 'db.read()' }] });
    expect(result.success).toBe(false);
    expect(JSON.stringify(result)).not.toContain('private-source-fragment');
  });

  it('rejects excluded paths in a repository map before invoking the model', async () => {
    const result = await selectFilesForArchitecture({ manifest: [{ path: '.env', size: 10 }], inspectedFiles: [], maxFiles: 30, maxBytes: 81920 });
    expect(result.success).toBe(false);
    expect(selectRelevantCodebaseFiles).not.toHaveBeenCalled();
  });

  it('returns a valid automatic selection without reading source on the server', async () => {
    const selection = { paths: ['api.ts'], reasoning: 'Read the API entry point.' };
    vi.mocked(selectRelevantCodebaseFiles).mockResolvedValue(selection);
    const input = { manifest: [{ path: 'api.ts', size: 9 }], inspectedFiles: [], maxFiles: 30, maxBytes: 81920 };
    expect(await selectFilesForArchitecture(input)).toEqual({ success: true, selection });
    expect(selectRelevantCodebaseFiles).toHaveBeenCalledWith(input);
  });

  it('hides provider messages during automatic selection', async () => {
    vi.mocked(selectRelevantCodebaseFiles).mockRejectedValue(new Error('private-source-fragment'));
    const result = await selectFilesForArchitecture({ manifest: [{ path: 'api.ts', size: 9 }], inspectedFiles: [], maxFiles: 30, maxBytes: 81920 });
    expect(result.success).toBe(false);
    expect(JSON.stringify(result)).not.toContain('private-source-fragment');
  });
});
