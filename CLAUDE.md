# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MAESTRO Threat Analyzer is an AI-powered threat modeling tool for Agentic AI systems. It analyzes system architectures across 7 MAESTRO framework layers (Foundation Models, Data Operations, Agent Frameworks, Deployment & Infrastructure, Evaluation & Observability, Security & Compliance, Agent Ecosystem) and generates threat assessments with mitigation recommendations.

## Development Commands

```bash
# Start development (requires BOTH commands in separate terminals)
npm run dev              # Next.js frontend on port 9002 with Turbopack
npm run genkit:dev       # Genkit AI flows backend

# Alternative: use genkit:watch for auto-reload during AI flow development
npm run genkit:watch

# Build and production
npm run build            # Production build
npm run start            # Run production server

# Code quality
npm run lint             # ESLint
npm run typecheck        # TypeScript type checking

# Testing
npm run test             # Run tests in watch mode
npm run test:run         # Run tests once
npm run test:coverage    # Run tests with coverage
```

## Environment Variables

Set `LLM_PROVIDER` to one of: `google`, `openai`, `anthropic`, `ollama`

Required API keys based on provider:
- Google: `GEMINI_API_KEY`
- OpenAI: `OPENAI_API_KEY`
- Anthropic: `ANTHROPIC_API_KEY`
- Ollama: `OLLAMA_SERVER_ADDRESS`

Optional: `LLM_MODEL` to override default model

Default models per provider: `gemini-2.5-flash` (google), `gpt-4o-mini` (openai),
`claude-opus-4-7` (anthropic), `qwen3:8b` (ollama).

**Note on the Anthropic default — read before changing it.** `@genkit-ai/anthropic`
registers catalogued models (`KNOWN_MODELS`) with `output: ['text','json']` and
`constrained: 'all'`; anything uncatalogued falls back to a generic profile
declaring text-only output and no constrained generation. Every flow in
`src/ai/flows/` defines an output schema, so an uncatalogued model shifts schema
enforcement from Genkit's native constrained path to its simulated one.

At plugin version 0.3.0 the catalog is:

```
claude-opus-4-7  claude-opus-4-6  claude-opus-4-5  claude-opus-4-1  claude-opus-4
claude-sonnet-4-6  claude-sonnet-4-5  claude-sonnet-4  claude-haiku-4-5
```

`claude-opus-5` and `claude-sonnet-5` are **not** in it. They work via `LLM_MODEL`,
but take the simulated path. Verify the catalog in
`node_modules/@genkit-ai/anthropic/lib/models.js` before moving the default —
the plugin's GitHub `main` branch is ahead of the published release, so reading
the repo rather than the installed package will mislead you. See issue #8.

## Architecture

**Dual-Process Architecture**: The app requires two concurrent processes - Next.js handles the frontend/server actions, Genkit handles AI flow execution.

**Key Directories**:
- `/src/ai/` - Genkit configuration and AI flows
  - `genkit.ts` - Provider setup (Google, OpenAI, Ollama)
  - `/flows/` - AI workflow definitions (threat analysis, mitigations, summaries)
- `/src/app/` - Next.js App Router
  - `actions.ts` - Server actions that invoke Genkit flows
  - `page.tsx` - Main application UI
- `/src/components/` - React components
  - `/ui/` - shadcn/ui component library
  - `error-boundary.tsx` - React Error Boundary for graceful error handling
- `/src/lib/` - Utilities and error handling
  - `errors.ts` - Typed error system (MaestroError, error codes, severity levels)
  - `ai-error-handler.ts` - AI/Genkit specific error classification
  - `retry-utils.ts` - Retry with exponential backoff
- `/src/data/` - MAESTRO layer definitions and use-case presets

**Data Flow**: User input → Server actions (`actions.ts`) → Genkit flows → AI analysis per MAESTRO layer → Streaming results to UI

## Tech Stack

- Next.js 15 with App Router and Turbopack
- TypeScript with strict mode
- Genkit AI framework with multi-provider support
- shadcn/ui components with Tailwind CSS
- Zod for schema validation

## Path Aliases

`@/*` maps to `./src/*`
