import { config } from 'dotenv';
config();

import '@/ai/flows/recommend-mitigations.ts';
import '@/ai/flows/suggest-threats-for-layer.ts';
import '@/ai/flows/generate-executive-summary.ts';
import '@/ai/flows/generate-architecture-diagram.ts';
import '@/ai/flows/extract-codebase-architecture.ts';
