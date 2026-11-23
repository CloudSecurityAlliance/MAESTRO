/**
 * Worked example for docs/validation-example.json.
 *
 * The runs describe a fictional system under test. They are hand-written
 * observations chosen to show each kind of outcome (pass, fail, not observed),
 * not measurements of any real product.
 */
import { evaluate, type ValidationReport } from '@/lib/validation/evaluate';
import type { ScenarioRun } from '@/lib/validation/schema';
import { AGENT_IDENTITY_SCENARIOS } from './agent-identity-scenarios';

export const EXAMPLE_SYSTEM = 'example-policy-gateway (fictional)';

export const EXAMPLE_SCENARIO_IDS = ['DEL-01', 'DEL-02', 'DEL-09', 'DEL-11', 'DEL-13', 'PI-02'] as const;

export const EXAMPLE_RUNS: ScenarioRun[] = [
  {
    scenarioId: 'DEL-01',
    observations: {
      enforcement: { decision: 'allow' },
      detection: { alerted: false },
      evidence: { verdict: 'preserved', verifier: 'example-verifier' },
    },
  },
  {
    scenarioId: 'DEL-02',
    observations: {
      enforcement: { decision: 'allow' },
      detection: { alerted: false },
      evidence: { verdict: 'preserved', verifier: 'example-verifier' },
    },
    evidenceBundle: {
      signedLinks: ['m-origin', 'm-child'],
      decisionRecord: { decision: 'allow', recordedAt: '2026-01-15T12:00:00.000Z' },
      effect: {
        status: 'performed',
        operation: 'export',
        resource: 'reports/2025-Q3/revenue.pdf',
        purpose: 'summarization',
        audience: 'tool:reports-api',
        at: '2026-01-15T12:00:01.000Z',
      },
      effectSource: 'independent',
      conflicts: [],
    },
    notes: ['The gateway trusted the child mandate’s scope without intersecting it with the parent.'],
  },
  {
    scenarioId: 'DEL-09',
    observations: {
      enforcement: { decision: 'deny' },
      detection: { alerted: true },
      evidence: { verdict: 'preserved', verifier: 'example-verifier' },
    },
  },
  {
    scenarioId: 'DEL-11',
    observations: {
      enforcement: { decision: 'deny' },
      detection: { alerted: true },
    },
  },
  {
    scenarioId: 'DEL-13',
    observations: {
      enforcement: { decision: 'allow' },
      evidence: { verdict: 'unresolved', verifier: 'example-verifier' },
    },
  },
  {
    scenarioId: 'PI-02',
    observations: {
      enforcement: { decision: 'allow' },
      detection: { alerted: true },
      evidence: { verdict: 'preserved', verifier: 'example-verifier' },
    },
  },
];

export interface ValidationExample {
  description: string;
  regenerate: string;
  input: { system: string; scenarioIds: readonly string[]; runs: ScenarioRun[] };
  output: ValidationReport;
}

export function buildValidationExample(): ValidationExample {
  const ids = new Set<string>(EXAMPLE_SCENARIO_IDS);
  const scenarios = AGENT_IDENTITY_SCENARIOS.filter((s) => ids.has(s.id));
  return {
    description:
      'Observed runs for six scenarios from a fictional system, and the deterministic report produced from them. ' +
      'The observations are illustrative, not measurements of a real system.',
    regenerate: 'UPDATE_VALIDATION_EXAMPLE=1 npx vitest run src/lib/validation',
    input: { system: EXAMPLE_SYSTEM, scenarioIds: EXAMPLE_SCENARIO_IDS, runs: EXAMPLE_RUNS },
    output: evaluate(scenarios, EXAMPLE_RUNS, { system: EXAMPLE_SYSTEM }),
  };
}
