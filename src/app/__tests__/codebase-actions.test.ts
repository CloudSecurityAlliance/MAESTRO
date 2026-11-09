import { beforeEach, describe, expect, it, vi } from 'vitest';
import { extractArchitectureFromCodebase } from '../codebase-actions';
import { extractCodebaseArchitecture } from '@/ai/flows/extract-codebase-architecture';

vi.mock('@/ai/flows/extract-codebase-architecture', () => ({ extractCodebaseArchitecture: vi.fn() }));

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
});
