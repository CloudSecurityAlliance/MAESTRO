import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { SidebarInputForm } from '../sidebar-input-form';
import { extractArchitectureFromCodebase } from '@/app/codebase-actions';

vi.mock('@/app/codebase-actions', () => ({ extractArchitectureFromCodebase: vi.fn() }));

function uploadSource() {
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
    await screen.findByText('Review the files below before sending them to the model.');
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
    await screen.findByText('Review the files below before sending them to the model.');
    fireEvent.click(screen.getByRole('checkbox', { name: 'api.ts' }));
    expect(screen.getByRole('button', { name: 'Extract Architecture' })).toBeDisabled();
    fireEvent.click(screen.getByRole('checkbox', { name: 'api.ts' }));
    fireEvent.click(screen.getByRole('button', { name: 'Extract Architecture' }));
    await screen.findByRole('alert');
    expect(screen.getByRole('textbox')).toHaveValue(original);
    expect(screen.getByRole('button', { name: 'Generate Analysis' })).toBeEnabled();
  });
});
