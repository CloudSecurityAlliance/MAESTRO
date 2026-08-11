import {genkit, type ModelArgument} from 'genkit';
import {googleAI} from '@genkit-ai/google-genai';
import openAI from '@genkit-ai/compat-oai/openai';
import {anthropic} from '@genkit-ai/anthropic';
import {ollama} from 'genkitx-ollama';

const provider = process.env.LLM_PROVIDER ?? 'google';

const config: {
  plugins: any[],
  model: ModelArgument<any>,
} = {
  plugins: [] as any[],
  model: '',
};

switch (provider) {
  case 'openai':
    config.plugins = [openAI({apiKey: process.env.OPENAI_API_KEY})];
    config.model = `openai/${process.env.LLM_MODEL || 'gpt-4o-mini'}`;
    break;
  case 'anthropic':
    config.plugins = [anthropic({apiKey: process.env.ANTHROPIC_API_KEY})];
    // Default is pinned to the highest-tier model in @genkit-ai/anthropic@0.3.0's
    // KNOWN_MODELS catalog. Catalogued models are registered with
    // ADVANCED_MODEL_INFO (output: ['text','json'], constrained: 'all'); anything
    // uncatalogued falls back to GENERIC_MODEL_INFO (text-only, no constrained
    // generation). Every flow in src/ai/flows/ declares an output schema, so an
    // uncatalogued model pushes schema enforcement onto Genkit's simulated
    // constrained generation instead of the native path.
    //
    // As of 0.3.0 the catalog stops at the 4.x line — claude-opus-5 and
    // claude-sonnet-5 are NOT in it. Setting LLM_MODEL to one of those works, but
    // takes the simulated path. Revisit this default when the plugin ships a
    // release cataloguing the Claude 5 models. See issue #8.
    config.model = anthropic.model(process.env.LLM_MODEL || 'claude-opus-4-7');
    break;
  case 'ollama':
    config.plugins = [ollama({
      serverAddress: process.env.OLLAMA_SERVER_ADDRESS || 'http://localhost:11434',
      models: [{
        name: process.env.LLM_MODEL || 'qwen3:8b',
        type: 'generate',
      }]
    })];
    config.model = `ollama/${process.env.LLM_MODEL || 'qwen3:8b'}`;
    break;
  default:
    config.plugins = [googleAI()];
    config.model = googleAI.model(process.env.LLM_MODEL || 'gemini-2.5-flash');
}

export const ai = genkit(config);
