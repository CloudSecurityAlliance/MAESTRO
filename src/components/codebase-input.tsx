'use client';

import React from 'react';
import { extractArchitectureFromCodebase } from '@/app/codebase-actions';
import { byteLength, prepareCodebase, type PreparedCodebase } from '@/lib/codebase';
import { Button } from '@/components/ui/button';
import { Spinner } from '@/components/icons';

type Props = {
  disabled: boolean;
  onBusyChange: (busy: boolean) => void;
  onArchitecture: (description: string) => void;
};

export function CodebaseInput({ disabled, onBusyChange, onArchitecture }: Props) {
  const [selection, setSelection] = React.useState<PreparedCodebase>({ files: [], skipped: [] });
  const [included, setIncluded] = React.useState<Set<string>>(new Set());
  const [busy, setBusy] = React.useState(false);
  const [message, setMessage] = React.useState('');
  const [error, setError] = React.useState('');
  const folderRef = React.useRef<HTMLInputElement>(null);
  React.useEffect(() => { folderRef.current?.setAttribute('webkitdirectory', ''); }, []);
  const locked = disabled || busy;
  const files = selection.files.filter(file => included.has(file.path));

  const setWorking = (value: boolean) => { setBusy(value); onBusyChange(value); };
  const chooseFiles = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const candidates = Array.from(event.target.files || []);
    event.target.value = '';
    if (!candidates.length) return;
    setWorking(true);
    setError('');
    setMessage('Reading selected files locally…');
    try {
      const prepared = await prepareCodebase(candidates);
      setSelection(prepared);
      setIncluded(new Set(prepared.files.map(file => file.path)));
      setMessage(prepared.files.length ? 'Review the files below before sending them to the model.' : 'No supported files were found. Review exclusions or choose another folder.');
    } catch {
      setSelection({ files: [], skipped: [] });
      setIncluded(new Set());
      setError('Could not read the selected files. Try a smaller folder.');
      setMessage('');
    } finally { setWorking(false); }
  };

  const extract = async () => {
    if (!files.length || locked) return;
    setWorking(true);
    setError('');
    setMessage('Extracting architecture from selected source files…');
    try {
      const result = await extractArchitectureFromCodebase({ files });
      if (!result.success) { setError(result.error); setMessage(''); return; }
      onArchitecture(result.architectureDescription);
      setMessage('Architecture inserted below. Review its evidence and unknowns, then choose Generate Analysis.');
    } catch {
      setError('The extraction request failed. Check your connection and try again.');
      setMessage('');
    } finally { setWorking(false); }
  };

  return (
    <section aria-labelledby="codebase-heading" className="space-y-3 rounded-md border p-3">
      <h2 id="codebase-heading" className="font-semibold text-sm">Start from source code</h2>
      <p className="text-xs text-muted-foreground">Choose a local folder or individual files. Nothing is sent until you select Extract Architecture.</p>
      <div className="space-y-2 text-xs">
        <label className="block">Choose codebase folder
          <input ref={folderRef} type="file" multiple disabled={locked} onChange={chooseFiles} className="mt-1 block w-full min-w-0" />
        </label>
        <label className="block">Or choose files
          <input type="file" multiple disabled={locked} onChange={chooseFiles} className="mt-1 block w-full min-w-0" />
        </label>
      </div>
      {selection.files.length > 0 && <>
        <p className="text-xs">{files.length} files selected ({(files.reduce((sum, file) => sum + byteLength(file.content), 0) / 1024).toFixed(1)} KiB)</p>
        <div className="max-h-56 overflow-auto space-y-2 rounded border p-2">
          {selection.files.map(file => <div key={file.path} className="text-xs">
            <label className="flex items-start gap-2 break-all">
              <input type="checkbox" checked={included.has(file.path)} disabled={locked} onChange={event => {
                const checked = event.target.checked;
                setIncluded(previous => { const next = new Set(previous); if (checked) next.add(file.path); else next.delete(file.path); return next; });
              }} />{file.path}
            </label>
            <details className="ml-5 mt-1"><summary className="cursor-pointer text-muted-foreground">Preview source</summary>
              <pre className="mt-1 max-h-48 overflow-auto whitespace-pre text-[11px]">{file.content}</pre>
            </details>
          </div>)}
        </div>
      </>}
      {selection.skipped.length > 0 && <details className="text-xs">
        <summary className="cursor-pointer">{selection.skipped.length} files excluded</summary>
        <ul className="mt-2 max-h-40 overflow-auto space-y-1">{selection.skipped.map((item, index) => <li key={index} className="break-all">{item.path}: {item.reason}</li>)}</ul>
      </details>}
      <p className="text-xs text-muted-foreground">Up to 60 files, 32 KiB each, 160 KiB total. Dependencies, build output and common credential files are excluded. Review source previews for embedded secrets; filtering cannot detect every secret.</p>
      <p className="text-xs text-muted-foreground">Extraction sends selected source to this app&apos;s server and its configured AI provider, including a cloud service if configured. It reads code without executing it. It does not inspect runtime behavior.</p>
      <Button type="button" variant="outline" className="w-full" disabled={locked || !files.length} onClick={extract}>
        {busy && <Spinner className="mr-2 h-4 w-4" />}Extract Architecture
      </Button>
      {message && <p role="status" className="text-xs">{message}</p>}
      {error && <p role="alert" className="text-xs text-destructive">{error}</p>}
    </section>
  );
}
