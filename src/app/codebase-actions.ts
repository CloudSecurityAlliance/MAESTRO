'use server';

import { extractCodebaseArchitecture } from '@/ai/flows/extract-codebase-architecture';
import { formatCodebaseArchitecture, validateCodebase } from '@/lib/codebase';
import { selectRelevantCodebaseFiles } from '@/ai/flows/select-codebase-files';
import { validateDiscoveryInput, type DiscoveryResult } from '@/lib/codebase-discovery';

type ExtractionResult = { success: true; architectureDescription: string } | { success: false; error: string };

export async function extractArchitectureFromCodebase(input: unknown): Promise<ExtractionResult> {
  let selection;
  try {
    selection = validateCodebase(input);
  } catch {
    return { success: false, error: 'Invalid source selection. Use up to 60 supported text files, 32 KiB per file and 160 KiB total. Exclude credential and generated files.' };
  }
  try {
    const result = await extractCodebaseArchitecture(selection);
    const architectureDescription = formatCodebaseArchitecture(result, selection.files, selection.discovery);
    if (architectureDescription.length > 5000) throw new Error('Description exceeds form limit');
    return { success: true, architectureDescription };
  } catch {
    // Do not expose provider errors that may include source code or prompt contents.
    return { success: false, error: 'Could not extract a valid architecture with source references. Check the configured model service, choose a smaller source selection, or retry.' };
  }
}

export async function selectFilesForArchitecture(input: unknown): Promise<DiscoveryResult> {
  let context;
  try {
    context = validateDiscoveryInput(input);
  } catch {
    return { success: false, error: 'Invalid repository map or source budget. Choose a smaller folder and retry.' };
  }
  try {
    return { success: true, selection: await selectRelevantCodebaseFiles(context) };
  } catch {
    return { success: false, error: 'The model could not select a valid set of source files within the limits. Try again, choose a smaller folder, or switch to manual selection.' };
  }
}
