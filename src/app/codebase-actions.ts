'use server';

import { extractCodebaseArchitecture } from '@/ai/flows/extract-codebase-architecture';
import { formatCodebaseArchitecture, validateCodebase } from '@/lib/codebase';

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
    const architectureDescription = formatCodebaseArchitecture(result, selection.files);
    if (architectureDescription.length > 5000) throw new Error('Description exceeds form limit');
    return { success: true, architectureDescription };
  } catch {
    // Do not expose provider errors that may include source code or prompt contents.
    return { success: false, error: 'Could not extract a valid architecture with source references. Check the configured model service, choose a smaller source selection, or retry.' };
  }
}
