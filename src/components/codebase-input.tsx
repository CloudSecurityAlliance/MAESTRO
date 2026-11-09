'use client';

import React from 'react';
import { extractArchitectureFromCodebase, selectFilesForArchitecture } from '@/app/codebase-actions';
import { byteLength, prepareCodebase, type PreparedCodebase } from '@/lib/codebase';
import { indexCodebase, type IndexedCodebase } from '@/lib/codebase-discovery';
import { discoverCodebase } from '@/lib/codebase-discovery-client';
import { Button } from '@/components/ui/button';
import { Spinner } from '@/components/icons';

type Props = {
  disabled: boolean;
  onBusyChange: (busy: boolean) => void;
  onArchitecture: (description: string) => void;
};

export function CodebaseInput({ disabled, onBusyChange, onArchitecture }: Props) {
  const [selection, setSelection] = React.useState<IndexedCodebase>({ entries: [], skipped: [] });
  const [mode, setMode] = React.useState<'automatic' | 'manual'>('automatic');
  const [reviewed, setReviewed] = React.useState<PreparedCodebase | null>(null);
  const [reasoning, setReasoning] = React.useState<string[]>([]);
  const [selectionVersion, setSelectionVersion] = React.useState(0);
  const [included, setIncluded] = React.useState<Set<string>>(new Set());
  const [busy, setBusy] = React.useState(false);
  const [message, setMessage] = React.useState('');
  const [error, setError] = React.useState('');
  const folderRef = React.useRef<HTMLInputElement>(null);
  React.useEffect(() => { folderRef.current?.setAttribute('webkitdirectory', ''); }, []);
  const locked = disabled || busy;
  const entries = selection.entries.filter(entry => included.has(entry.path));

  const setWorking = (value: boolean) => { setBusy(value); onBusyChange(value); };
  const chooseFiles = (event: React.ChangeEvent<HTMLInputElement>) => {
    const candidates = Array.from(event.target.files || []);
    event.target.value = '';
    if (!candidates.length) return;
    setSelectionVersion(version => version + 1);
    setError('');
    setReviewed(null);
    setReasoning([]);
    try {
      const prepared = indexCodebase(candidates);
      setSelection(prepared);
      setIncluded(new Set(prepared.entries.map(entry => entry.path)));
      setMessage(prepared.entries.length ? 'Repository map ready. No files have been sent. You can extract automatically or review exclusions first.' : 'No supported files were found. Review exclusions or choose another folder.');
    } catch {
      setSelection({ entries: [], skipped: [] });
      setIncluded(new Set());
      setError('Could not read the selected files. Try a smaller folder.');
      setMessage('');
    }
  };

  const extract = async () => {
    if (!entries.length || locked) return;
    setWorking(true);
    setError('');
    setReviewed(null);
    setReasoning([]);
    try {
      let prepared: PreparedCodebase;
      let discovery;
      if (mode === 'automatic') {
        const run = await discoverCodebase(entries, selectFilesForArchitecture, setMessage);
        prepared = run;
        discovery = { mappedFiles: run.mappedFiles, selectionPasses: run.selectionPasses };
        setReasoning(run.reasoning);
      } else {
        setMessage('Reading selected files locally…');
        prepared = await prepareCodebase(entries.map(entry => entry.file));
      }
      setReviewed(prepared);
      if (!prepared.files.length) throw new Error('No readable source files remain. Choose another folder or file selection.');
      setMessage(`Extracting architecture from ${prepared.files.length} source files…`);
      const result = await extractArchitectureFromCodebase({ files: prepared.files, ...(discovery ? { discovery } : {}) });
      if (!result.success) { setError(result.error); setMessage(''); return; }
      onArchitecture(result.architectureDescription);
      setMessage('Architecture inserted below. Review its evidence and unknowns, then choose Generate Analysis.');
    } catch {
      setError('Automatic selection or extraction could not complete. Check the model connection, choose a smaller folder, or try manual selection.');
      setMessage('');
    } finally { setWorking(false); }
  };

  return (
    <section aria-labelledby="codebase-heading" className="space-y-3 rounded-md border p-3">
      <h2 id="codebase-heading" className="font-semibold text-sm">Start from source code</h2>
      <p className="text-xs text-muted-foreground">Choose your repository folder once. The model can select relevant files and follow their imports before extracting the architecture. Nothing is sent until you select Extract Architecture.</p>
      <div className="space-y-2 text-xs">
        <label className="block">Choose codebase folder
          <input ref={folderRef} type="file" multiple disabled={locked} onChange={chooseFiles} className="mt-1 block w-full min-w-0" />
        </label>
        <label className="block">Or choose files
          <input type="file" multiple disabled={locked} onChange={chooseFiles} className="mt-1 block w-full min-w-0" />
        </label>
      </div>
      <label className="block text-xs">File selection
        <select value={mode} disabled={locked} onChange={event => { setMode(event.target.value as 'automatic' | 'manual'); setReviewed(null); setReasoning([]); }} className="mt-1 block w-full rounded border bg-background p-2">
          <option value="automatic">Automatic (recommended)</option>
          <option value="manual">Manual selection</option>
        </select>
      </label>
      {selection.entries.length > 0 && <>
        <p className="text-xs">{entries.length} eligible files in the repository map. {mode === 'automatic' ? 'The model chooses which source files to read.' : 'Checked files will be read within the source limits.'}</p>
        <details>
        <summary className="cursor-pointer text-xs">Review or exclude files (optional)</summary>
        <div className="max-h-56 overflow-auto space-y-2 rounded border p-2">
          {selection.entries.map(entry => <div key={`${selectionVersion}:${entry.path}`} className="text-xs">
            <label className="flex items-start gap-2 break-all">
              <input type="checkbox" checked={included.has(entry.path)} disabled={locked} onChange={event => {
                const checked = event.target.checked;
                setIncluded(previous => { const next = new Set(previous); if (checked) next.add(entry.path); else next.delete(entry.path); return next; });
                setReviewed(null);
                setReasoning([]);
              }} />{entry.path}
            </label>
            <SourcePreview entry={entry} />
          </div>)}
        </div>
        </details>
      </>}
      {selection.skipped.length > 0 && <details className="text-xs">
        <summary className="cursor-pointer">{selection.skipped.length} files excluded</summary>
        <ul className="mt-2 max-h-40 overflow-auto space-y-1">{selection.skipped.map((item, index) => <li key={index} className="break-all">{item.path}: {item.reason}</li>)}</ul>
      </details>}
      {reviewed && <details className="text-xs" open>
        <summary className="cursor-pointer">{reviewed.files.length} source files read from {entries.length} mapped files ({(reviewed.files.reduce((sum, file) => sum + byteLength(file.content), 0) / 1024).toFixed(1)} KiB)</summary>
        <ul className="mt-2 max-h-40 overflow-auto space-y-1">{reviewed.files.map(file => <li key={file.path} className="break-all">{file.path}</li>)}</ul>
        {reviewed.skipped.map((file, index) => <p key={index} className="mt-1 break-all">Skipped {file.path}: {file.reason}</p>)}
        {reasoning.map((text, index) => <p key={index} className="mt-2">Selection pass {index + 1}: {text}</p>)}
      </details>}
      <p className="text-xs text-muted-foreground">Automatic mode maps up to 2,000 eligible paths (192 KiB of metadata), then reads up to 60 files over two selection passes. Source limits: 32 KiB per file, 160 KiB total. This is selective review, not an exhaustive scan.</p>
      <p className="text-xs text-muted-foreground">Dependencies, build output and common credential files are excluded. Preview and exclude sensitive files before extraction; filename filtering cannot detect embedded secrets.</p>
      <p className="text-xs text-muted-foreground">Clicking Extract Architecture sends the file map and model-selected source to this app&apos;s server and configured AI provider, which may be a cloud service. The follow-up pass can request additional eligible files automatically. Source is never executed.</p>
      <Button type="button" variant="outline" className="w-full" disabled={locked || !entries.length} onClick={extract}>
        {busy && <Spinner className="mr-2 h-4 w-4" />}Extract Architecture
      </Button>
      {message && <p role="status" className="text-xs">{message}</p>}
      {error && <p role="alert" className="text-xs text-destructive">{error}</p>}
    </section>
  );
}

function SourcePreview({ entry }: { entry: IndexedCodebase['entries'][number] }) {
  const [content, setContent] = React.useState<string | null>(null);
  return <details className="ml-5 mt-1" onToggle={async event => {
    if (!event.currentTarget.open || content !== null) return;
    setContent('Reading locally…');
    try { setContent(await entry.file.text()); } catch { setContent('Could not read file.'); }
  }}><summary className="cursor-pointer text-muted-foreground">Preview source</summary>
    <pre className="mt-1 max-h-48 overflow-auto whitespace-pre text-[11px]">{content}</pre>
  </details>;
}
