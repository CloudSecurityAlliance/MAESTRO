import { describe, expect, it, vi } from 'vitest';
import {
  CODEBASE_LIMITS, fileExclusionReason, prepareCodebase, validateCodebase,
  validateCodebaseOutput, formatCodebaseArchitecture, type CodebaseOutput,
} from '../codebase';

const files = [{ path: 'src/api.ts', content: 'export function handler() {\n  return db.read();\n}' }];
const output: CodebaseOutput = {
  architecture: 'The application defines an API handler that reads from a data store. Deployment permissions are unknown.',
  evidence: [{ path: 'src/api.ts', startLine: 1, endLine: 3, observation: 'The handler calls db.read().' }],
  uncertainties: ['Database permissions and authentication are not shown.'],
};

describe('codebase boundaries', () => {
  it.each(['.env', '.env.local', 'config/credentials.json', '.aws/config', 'id_rsa', 'cert.key',
    'node_modules/lib/index.js', '.git/config', 'dist/index.js', 'package-lock.json',
    '../server.ts', '/server.ts', 'C:/server.ts', 'src\\server.ts', 'src//a.ts', 'a\n.ts', 'image.png'])
  ('excludes %s on the server as well as the client', path => {
    expect(fileExclusionReason(path)).not.toBeNull();
    expect(() => validateCodebase({ files: [{ path, content: 'data' }] })).toThrow();
  });

  it.each(['src/api.ts', 'src/app.py', 'Dockerfile', 'package.json', 'infra/main.tf', 'go.mod'])
  ('accepts source/configuration path %s', path => {
    expect(validateCodebase({ files: [{ path, content: 'content' }] }).files).toHaveLength(1);
  });

  it('enforces UTF-8 byte limits rather than character counts', () => {
    expect(() => validateCodebase({ files: [{ path: 'a.ts', content: '界'.repeat(12000) }] })).toThrow('File exceeds');
  });

  it('rejects oversized, duplicate, binary and empty selections', () => {
    expect(() => validateCodebase({ files: [] })).toThrow();
    expect(() => validateCodebase({ files: [...files, ...files] })).toThrow('Duplicate');
    expect(() => validateCodebase({ files: [{ path: 'a.ts', content: 'a\0b' }] })).toThrow('Binary');
    expect(() => validateCodebase({ files: Array.from({ length: 6 }, (_, i) => ({ path: `${i}.ts`, content: 'a'.repeat(CODEBASE_LIMITS.fileBytes) })) })).toThrow('selection exceeds');
    expect(() => validateCodebase({ files: Array.from({ length: 61 }, (_, i) => ({ path: `${i}.ts`, content: 'a' })) })).toThrow();
  });

  it('never reads excluded files and reports partial coverage', async () => {
    const secretRead = vi.fn().mockResolvedValue('secret');
    const result = await prepareCodebase([
      { name: '.env', webkitRelativePath: 'repo/.env', size: 6, text: secretRead },
      { name: 'api.ts', webkitRelativePath: 'repo/src/api.ts', size: 10, text: async () => 'const x=1;' },
      { name: 'large.ts', size: 40000, text: secretRead },
    ]);
    expect(secretRead).not.toHaveBeenCalled();
    expect(result.files).toEqual([{ path: 'src/api.ts', content: 'const x=1;' }]);
    expect(result.skipped).toHaveLength(2);
  });

  it('reports unreadable and binary files without losing valid files', async () => {
    const result = await prepareCodebase([
      { name: 'a.ts', size: 1, text: async () => { throw new Error('read failure'); } },
      { name: 'b.ts', size: 3, text: async () => 'a\0b' },
      { name: 'c.ts', size: 1, text: async () => 'c' },
    ]);
    expect(result.files.map(file => file.path)).toEqual(['c.ts']);
    expect(result.skipped).toHaveLength(2);
  });
});

describe('source evidence', () => {
  it('accepts existing references and carries them into the analysis description', () => {
    const result = validateCodebaseOutput(output, files);
    const text = formatCodebaseArchitecture(result, files);
    expect(text).toContain('src/api.ts:1-3');
    expect(text).toContain('Coverage: 1 files');
    expect(text).toContain('Unknowns / assumptions');
    expect(text.length).toBeLessThanOrEqual(5000);
  });

  it.each([
    { path: 'invented.ts', startLine: 1, endLine: 1 },
    { path: 'src/api.ts', startLine: 1, endLine: 4 },
    { path: 'src/api.ts', startLine: 3, endLine: 1 },
    { path: 'src/api.ts', startLine: 0, endLine: 1 },
  ])('rejects invalid reference %j', reference => {
    expect(() => validateCodebaseOutput({ ...output, evidence: [{ ...output.evidence[0], ...reference }] }, files)).toThrow();
  });

  it('fits maximum schema output within the existing form limit', () => {
    const maximum: CodebaseOutput = {
      architecture: 'a'.repeat(2200),
      evidence: Array.from({ length: 6 }, () => ({ path: 'p'.repeat(160), startLine: 100000, endLine: 100000, observation: 'o'.repeat(140) })),
      uncertainties: Array(3).fill('u'.repeat(120)),
    };
    expect(formatCodebaseArchitecture(maximum, files).length).toBeLessThanOrEqual(5000);
  });
});
