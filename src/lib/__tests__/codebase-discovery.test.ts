import { describe, expect, it, vi } from 'vitest';
import { byteLength, type LocalSourceFile } from '../codebase';
import {
  DISCOVERY_LIMITS, indexCodebase, validateDiscoveryInput, validateDiscoveryOutput,
  type DiscoveryInput, type DiscoveryResult,
} from '../codebase-discovery';
import { discoverCodebase } from '../codebase-discovery-client';

const input: DiscoveryInput = {
  manifest: [{ path: 'api.ts', size: 9 }, { path: 'db.ts', size: 12 }],
  inspectedFiles: [], maxFiles: 30, maxBytes: 81920,
};
const chosen = (paths: string[]): DiscoveryResult => ({ success: true, selection: { paths, reasoning: 'Follow application dependencies.' } });
const local = (name: string, content: string): LocalSourceFile => ({ name, size: byteLength(content), text: vi.fn().mockResolvedValue(content) });

describe('repository map', () => {
  it('indexes more than 60 eligible files without reading contents', () => {
    const read = vi.fn();
    const result = indexCodebase(Array.from({ length: 100 }, (_, i) => ({ name: `file${i}.ts`, size: 10, text: read })));
    expect(result.entries).toHaveLength(100);
    expect(read).not.toHaveBeenCalled();
  });

  it('filters excluded files before the model receives the map', () => {
    const result = indexCodebase([local('.env', 'secret'), local('package-lock.json', 'lock'), local('api.ts', 'content')]);
    expect(result.entries.map(entry => entry.path)).toEqual(['api.ts']);
    expect(result.skipped).toHaveLength(2);
  });

  it('reports map overflow and retains a manifest beyond alphabetical source files', () => {
    const candidates = Array.from({ length: 2005 }, (_, i) => local(`a${i}.ts`, 'source'));
    const result = indexCodebase([...candidates, local('package.json', '{}')]);
    expect(result.entries).toHaveLength(DISCOVERY_LIMITS.mapFiles);
    expect(result.entries[0].path).toBe('package.json');
    expect(result.skipped).toHaveLength(6);
    expect(result.skipped[0].reason).toContain('map limit');
  });

  it('caps metadata by UTF-8 bytes as well as path count', () => {
    const candidates = Array.from({ length: 2000 }, (_, i) => local(`${'界'.repeat(140)}${i}.ts`, 'source'));
    const result = indexCodebase(candidates);
    const manifest = result.entries.map(entry => ({ path: entry.path, size: entry.file.size }));
    expect(result.entries.length).toBeGreaterThan(0);
    expect(result.skipped.length).toBeGreaterThan(0);
    expect(byteLength(JSON.stringify(manifest))).toBeLessThanOrEqual(DISCOVERY_LIMITS.mapBytes);
  });
});

describe('discovery validation', () => {
  it.each(['.env', '../api.ts', '/api.ts', 'node_modules/api.ts'])('rejects prohibited map path %s', path => {
    expect(() => validateDiscoveryInput({ ...input, manifest: [{ path, size: 9 }] })).toThrow();
  });
  it('rejects duplicate map entries and context outside the map', () => {
    expect(() => validateDiscoveryInput({ ...input, manifest: [input.manifest[0], input.manifest[0]] })).toThrow();
    expect(() => validateDiscoveryInput({ ...input, inspectedFiles: [{ path: 'other.ts', content: 'x' }] })).toThrow();
  });
  it('enforces the combined source budget and smaller discovery context', () => {
    expect(() => validateDiscoveryInput({ ...input, inspectedFiles: [{ path: 'api.ts', content: 'a'.repeat(32768) }], maxBytes: 163840 })).toThrow('budget');
    const manifest = Array.from({ length: 3 }, (_, i) => ({ path: `${i}.ts`, size: 32768 }));
    expect(() => validateDiscoveryInput({ manifest, inspectedFiles: manifest.map(file => ({ path: file.path, content: 'a'.repeat(32768) })), maxFiles: 30, maxBytes: 1 })).toThrow('context');
  });
  it.each([['missing.ts'], ['../api.ts'], ['api.ts', 'api.ts']])('rejects invented or duplicate selected paths %j', (...paths) => {
    expect(() => validateDiscoveryOutput({ paths, reasoning: 'selection' }, input)).toThrow();
  });
  it('rejects over-budget selections, repeats and an empty initial selection', () => {
    expect(() => validateDiscoveryOutput({ paths: ['api.ts', 'db.ts'], reasoning: 'selection' }, { ...input, maxBytes: 10 })).toThrow();
    expect(() => validateDiscoveryOutput({ paths: ['api.ts'], reasoning: 'selection' }, { ...input, inspectedFiles: [{ path: 'api.ts', content: 'db.read()' }] })).toThrow();
    expect(() => validateDiscoveryOutput({ paths: [], reasoning: 'selection' }, input)).toThrow();
    expect(() => validateDiscoveryOutput({ paths: ['api.ts', 'db.ts'], reasoning: 'selection' }, { ...input, maxFiles: 1 })).toThrow();
  });
});

describe('automatic discovery', () => {
  it('reads only model-selected files and supplies first-pass source to follow-up', async () => {
    const first = local('api.ts', 'import db from "./db";');
    const second = local('db.ts', 'export default db;');
    const unused = local('unused.ts', 'unrelated');
    const selector = vi.fn().mockResolvedValueOnce(chosen(['api.ts'])).mockResolvedValueOnce(chosen(['db.ts']));
    const result = await discoverCodebase(indexCodebase([first, second, unused]).entries, selector, vi.fn());
    expect(result.files.map(file => file.path)).toEqual(['api.ts', 'db.ts']);
    expect(result.selectionPasses).toBe(2);
    expect(result.mappedFiles).toBe(3);
    expect(unused.text).not.toHaveBeenCalled();
    expect(selector.mock.calls[1][0].inspectedFiles).toEqual([{ path: 'api.ts', content: 'import db from "./db";' }]);
  });
  it('rejects an invalid model path before reading any file', async () => {
    const file = local('api.ts', 'content');
    await expect(discoverCodebase(indexCodebase([file]).entries, vi.fn().mockResolvedValue(chosen(['../api.ts'])), vi.fn())).rejects.toThrow();
    expect(file.text).not.toHaveBeenCalled();
  });
  it('accepts an empty follow-up and never loops beyond two calls', async () => {
    const selector = vi.fn().mockResolvedValueOnce(chosen(['api.ts'])).mockResolvedValueOnce(chosen([]));
    const result = await discoverCodebase(indexCodebase([local('api.ts', 'source'), local('db.ts', 'source')]).entries, selector, vi.fn());
    expect(result.files).toHaveLength(1);
    expect(selector).toHaveBeenCalledTimes(2);
  });
  it('does not request another pass when every eligible file was already read', async () => {
    const selector = vi.fn().mockResolvedValue(chosen(['api.ts']));
    const result = await discoverCodebase(indexCodebase([local('api.ts', 'source')]).entries, selector, vi.fn());
    expect(result.selectionPasses).toBe(1);
    expect(selector).toHaveBeenCalledTimes(1);
  });
  it('reports unreadable selected files and excludes them from follow-up', async () => {
    const bad = local('bad.ts', 'a\0b');
    const selector = vi.fn().mockResolvedValueOnce(chosen(['api.ts', 'bad.ts'])).mockResolvedValueOnce(chosen(['db.ts']));
    const result = await discoverCodebase(indexCodebase([local('api.ts', 'source'), bad, local('db.ts', 'data')]).entries, selector, vi.fn());
    expect(result.files.map(file => file.path)).toEqual(['api.ts', 'db.ts']);
    expect(result.skipped[0].path).toBe('bad.ts');
    expect(selector.mock.calls[1][0].manifest.map((file: { path: string }) => file.path)).not.toContain('bad.ts');
  });
  it('stops on a provider failure instead of sending the entire repository', async () => {
    const file = local('api.ts', 'source');
    await expect(discoverCodebase(indexCodebase([file]).entries, vi.fn().mockResolvedValue({ success: false, error: 'Model unavailable' }), vi.fn())).rejects.toThrow('Model unavailable');
    expect(file.text).not.toHaveBeenCalled();
  });
});
