import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { SidebarInputForm } from '../sidebar-input-form';
import { extractArchitectureFromCodebase, selectFilesForArchitecture } from '@/app/codebase-actions';

vi.mock('@/app/codebase-actions', () => ({ extractArchitectureFromCodebase: vi.fn(), selectFilesForArchitecture: vi.fn() }));

function uploadSource() {
  fireEvent.change(screen.getByLabelText('File selection'), { target: { value: 'manual' } });
  fireEvent.change(screen.getByLabelText('Or choose files'), { target: { files: [
    { name: 'api.ts', size: 9, text: async () => 'db.read()' },
    { name: '.env', size: 10, text: async () => 'SECRET=123' },
  ] } });
}

describe('source code to existing analysis workflow', () => {
  beforeEach(() => vi.resetAllMocks());

  it('prepares locally, extracts only selected files, then submits reviewed architecture', async () => {
    const architecture = 'Architecture inferred from source. An API uses a database. Evidence: api.ts:1-1. Runtime permissions are unknown.';
    vi.mocked(extractArchitectureFromCodebase).mockResolvedValue({ success: true, architectureDescription: architecture });
    const analyze = vi.fn().mockResolvedValue(undefined);
    render(<SidebarInputForm onAnalyze={analyze} onStop={vi.fn()} isAnalyzing={false} buttonText="Generate Analysis" onDescriptionChange={vi.fn()} />);
    uploadSource();
    await screen.findByText(/Repository map ready/);
    expect(extractArchitectureFromCodebase).not.toHaveBeenCalled();
    expect(screen.getByText('1 files excluded')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Extract Architecture' }));
    await waitFor(() => expect(screen.getByRole('textbox')).toHaveValue(architecture));
    expect(extractArchitectureFromCodebase).toHaveBeenCalledWith({ files: [{ path: 'api.ts', content: 'db.read()' }] });
    expect(analyze).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Generate Analysis' }));
    await waitFor(() => expect(analyze).toHaveBeenCalledWith(architecture));
  });

  it('lets users exclude source and keeps the existing description after a failed extraction', async () => {
    vi.mocked(extractArchitectureFromCodebase).mockResolvedValue({ success: false, error: 'Model unavailable' });
    render(<SidebarInputForm onAnalyze={vi.fn()} onStop={vi.fn()} isAnalyzing={false} buttonText="Generate Analysis" onDescriptionChange={vi.fn()} />);
    const original = (screen.getByRole('textbox') as HTMLTextAreaElement).value;
    uploadSource();
    await screen.findByText(/Repository map ready/);
    fireEvent.click(screen.getByText('Review or exclude files (optional)'));
    fireEvent.click(screen.getByRole('checkbox', { name: 'api.ts' }));
    expect(screen.getByRole('button', { name: 'Extract Architecture' })).toBeDisabled();
    fireEvent.click(screen.getByRole('checkbox', { name: 'api.ts' }));
    fireEvent.click(screen.getByRole('button', { name: 'Extract Architecture' }));
    await screen.findByRole('alert');
    expect(screen.getByRole('textbox')).toHaveValue(original);
    expect(screen.getByRole('button', { name: 'Generate Analysis' })).toBeEnabled();
  });

  it('automatically selects entry points and related files after one folder selection', async () => {
    const apiRead = vi.fn().mockResolvedValue('import db from "./db";');
    const dbRead = vi.fn().mockResolvedValue('export default database;');
    const unusedRead = vi.fn().mockResolvedValue('unused');
    const secretRead = vi.fn();
    const architecture = 'An API imports a database module. Source evidence: src/api.ts:1-1 and src/db.ts:1-1. Deployment is unknown.';
    vi.mocked(selectFilesForArchitecture)
      .mockResolvedValueOnce({ success: true, selection: { paths: ['src/api.ts'], reasoning: 'Read the entry point.' } })
      .mockResolvedValueOnce({ success: true, selection: { paths: ['src/db.ts'], reasoning: 'Follow the database import.' } });
    vi.mocked(extractArchitectureFromCodebase).mockResolvedValue({ success: true, architectureDescription: architecture });
    const analyze = vi.fn();
    render(<SidebarInputForm onAnalyze={analyze} onStop={vi.fn()} isAnalyzing={false} buttonText="Generate Analysis" onDescriptionChange={vi.fn()} />);
    expect(screen.getByLabelText('File selection')).toHaveValue('automatic');
    fireEvent.change(screen.getByLabelText('Choose codebase folder'), { target: { files: [
      { name: 'api.ts', webkitRelativePath: 'repo/src/api.ts', size: 22, text: apiRead },
      { name: 'db.ts', webkitRelativePath: 'repo/src/db.ts', size: 24, text: dbRead },
      { name: 'unused.ts', webkitRelativePath: 'repo/src/unused.ts', size: 6, text: unusedRead },
      { name: '.env', webkitRelativePath: 'repo/.env', size: 10, text: secretRead },
    ] } });
    expect(apiRead).not.toHaveBeenCalled();
    expect(selectFilesForArchitecture).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Extract Architecture' }));
    await waitFor(() => expect(screen.getByRole('textbox')).toHaveValue(architecture));
    expect(selectFilesForArchitecture).toHaveBeenCalledTimes(2);
    expect(vi.mocked(selectFilesForArchitecture).mock.calls[1][0]).toMatchObject({ inspectedFiles: [{ path: 'src/api.ts', content: 'import db from "./db";' }] });
    expect(extractArchitectureFromCodebase).toHaveBeenCalledWith({
      files: [{ path: 'src/api.ts', content: 'import db from "./db";' }, { path: 'src/db.ts', content: 'export default database;' }],
      discovery: { mappedFiles: 3, selectionPasses: 2 },
    });
    expect(unusedRead).not.toHaveBeenCalled();
    expect(secretRead).not.toHaveBeenCalled();
    expect(screen.getByText(/2 source files read from 3 mapped files/)).toBeInTheDocument();
    expect(analyze).not.toHaveBeenCalled();
  });
});
