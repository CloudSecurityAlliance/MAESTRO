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

## Architecture

**Dual-Process Architecture**: The app requires two concurrent processes - Next.js handles the frontend/server actions, Genkit handles AI flow execution.

**Key Directories**:
- `/src/ai/` - Genkit configuration and AI flows
  - `genkit.ts` - Provider setup (Google, OpenAI, Anthropic, Ollama)
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
