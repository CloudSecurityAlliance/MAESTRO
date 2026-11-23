import { describe, it, expect } from 'vitest';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { ZodError } from 'zod';
import { AGENT_IDENTITY_SCENARIOS } from '@/data/validation/agent-identity-scenarios';
import { buildValidationExample } from '@/data/validation/example';
import { PLAN_NOTE, buildTestPlan, deriveExpectation, evaluate, rate } from '../evaluate';
import type { EvidenceBundle, ScenarioRun, SecurityScenario } from '../schema';

const scenarios = AGENT_IDENTITY_SCENARIOS;
const byId = (id: string): SecurityScenario => scenarios.find((s) => s.id === id)!;

/** A run whose observations match the oracle exactly. */
const idealRun = (s: SecurityScenario): ScenarioRun => {
  const d = deriveExpectation(s);
  return {
    scenarioId: s.id,
    observations: {
      enforcement: { decision: d.enforcement },
      detection: { alerted: d.detection === 'alert' },
      evidence: { verdict: d.evidence, verifier: 'test' },
    },
  };
};

const performedExport = (): EvidenceBundle => ({
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
});

describe('evaluate: aggregate scoring', () => {
  it('passes every dimension for a system that matches the oracle', () => {
    const report = evaluate(scenarios, scenarios.map(idealRun));
    expect(report.failures).toEqual([]);
    expect(report.notObserved).toEqual([]);
    for (const dim of ['detection', 'enforcement', 'evidence'] as const) {
      expect(report.dimensions[dim]).toMatchObject({ total: scenarios.length, pass: scenarios.length, fail: 0 });
      expect(report.dimensions[dim].passRate).toEqual(rate(scenarios.length, scenarios.length));
    }
    const valid = scenarios.filter((s) => s.expected.enforcement === 'allow').length;
    expect(report.falsePositiveBlocking).toEqual({ numerator: 0, denominator: valid, value: 0 });
  });

  it('reports nothing as passed when nothing was observed', () => {
    const report = evaluate(scenarios, []);
    for (const dim of ['detection', 'enforcement', 'evidence'] as const) {
      expect(report.dimensions[dim]).toMatchObject({ pass: 0, fail: 0, notObserved: scenarios.length });
      expect(report.dimensions[dim].passRate).toEqual({ numerator: 0, denominator: 0, value: null });
      expect(report.dimensions[dim].observedCoverage).toEqual({ numerator: 0, denominator: scenarios.length, value: 0 });
    }
    expect(report.notObserved).toHaveLength(scenarios.length);
    expect(report.falsePositiveBlocking.value).toBeNull();
  });

  it('gives explicit denominators per family and for the delegation suite', () => {
    const report = evaluate(scenarios, scenarios.map(idealRun));
    const family = report.byFamily.delegation_escalation;
    const count = scenarios.filter((s) => s.threatFamily === 'delegation_escalation').length;
    expect(family.scenarios).toBe(count);
    expect(family.dimensions.enforcement.passRate).toEqual(rate(count, count));
    const suiteCount = scenarios.filter((s) => s.suites.includes('delegation')).length;
    expect(report.bySuite.delegation.scenarios).toBe(suiteCount);
    expect(Object.values(report.byFamily).reduce((n, f) => n + f.scenarios, 0)).toBe(scenarios.length);
  });

  it('does not produce a combined score', () => {
    const report = evaluate(scenarios, scenarios.map(idealRun));
    expect(Object.keys(report)).not.toContain('score');
    expect(report.disclaimer).toMatch(/not a security certification/);
  });

  it('is deterministic', () => {
    const runs = scenarios.map(idealRun);
    expect(evaluate(scenarios, runs)).toEqual(evaluate(scenarios, structuredClone(runs)));
  });
});

describe('evaluate: each dimension is scored independently', () => {
  it('flags over-blocking of a valid request as a false deny and counts it', () => {
    const s = byId('DEL-11');
    const run = idealRun(s);
    run.observations.enforcement = { decision: 'deny' };
    const report = evaluate([s], [run]);
    expect(report.results[0].dimensions.enforcement).toMatchObject({ outcome: 'fail', failureKind: 'false_deny' });
    expect(report.results[0].dimensions.detection.outcome).toBe('pass');
    expect(report.falsePositiveBlocking).toEqual({ numerator: 1, denominator: 1, value: 1 });
  });

  it('reports a performed escalation as false allow and the overclaimed verdict as a separate failure', () => {
    const s = byId('DEL-02');
    const report = evaluate(
      [s],
      [
        {
          scenarioId: s.id,
          observations: {
            enforcement: { decision: 'allow' },
            detection: { alerted: false },
            evidence: { verdict: 'preserved', verifier: 'sut-verifier' },
          },
          evidenceBundle: performedExport(),
        },
      ],
    );
    const kinds = report.failures.map((f) => [f.dimension, f.failureKind]);
    expect(kinds).toEqual([
      ['detection', 'missed_detection'],
      ['enforcement', 'false_allow'],
      ['evidence', 'overclaimed_authority'],
    ]);
    const evidence = report.failures.find((f) => f.dimension === 'evidence')!;
    expect(evidence).toMatchObject({ scenarioId: 'DEL-02', expected: 'violated', observed: 'preserved' });
    expect(evidence.failedChecks).toEqual(['delegation.link_exceeds_parent', 'delegation.operation_outside_scope']);
  });

  it('fails enforcement when the system reports deny but the prohibited effect still happened', () => {
    const s = byId('DEL-02');
    const run: ScenarioRun = { ...idealRun(s), evidenceBundle: performedExport() };
    run.observations.evidence = { verdict: 'violated', verifier: 'sut-verifier' };
    const report = evaluate([s], [run]);
    expect(report.results[0].dimensions.enforcement).toMatchObject({ outcome: 'fail', failureKind: 'enforcement_bypass' });
    expect(report.results[0].dimensions.detection.outcome).toBe('pass');
    expect(report.results[0].dimensions.evidence.outcome).toBe('pass');
  });

  it('fails enforcement when only the effect, not the decision, was observed', () => {
    const s = byId('DEL-02');
    const report = evaluate([s], [{ scenarioId: s.id, observations: {}, evidenceBundle: performedExport() }]);
    expect(report.results[0].dimensions.enforcement).toMatchObject({ outcome: 'fail', failureKind: 'enforcement_bypass' });
    expect(report.results[0].dimensions.detection.outcome).toBe('not_observed');
  });

  it('separates detection from enforcement for an in-scope injected instruction', () => {
    const s = byId('PI-02');
    const run = idealRun(s);
    run.observations.detection = { alerted: false };
    const report = evaluate([s], [run]);
    expect(report.results[0].dimensions.enforcement.outcome).toBe('pass');
    expect(report.results[0].dimensions.detection).toMatchObject({ outcome: 'fail', failureKind: 'missed_detection' });
  });

  it('flags an alert on a valid request as a false alert', () => {
    const s = byId('DEL-01');
    const run = idealRun(s);
    run.observations.detection = { alerted: true };
    expect(evaluate([s], [run]).failures).toMatchObject([{ dimension: 'detection', failureKind: 'false_alert' }]);
  });

  it('rejects a preserved verdict where evidence is missing and names what is missing', () => {
    const s = byId('DEL-09');
    const run = idealRun(s);
    run.observations.evidence = { verdict: 'preserved', verifier: 'sut-verifier' };
    const [failure] = evaluate([s], [run]).failures;
    expect(failure).toMatchObject({ dimension: 'evidence', failureKind: 'overclaimed_authority', expected: 'unresolved' });
    expect(failure.missingEvidence).toEqual(['signed delegation link for mandate m-origin']);
  });

  it('distinguishes the other evidence mismatches', () => {
    const kind = (id: string, verdict: 'preserved' | 'violated' | 'unresolved', bundle?: EvidenceBundle) => {
      const s = byId(id);
      const run: ScenarioRun = { ...idealRun(s), evidenceBundle: bundle };
      run.observations.evidence = { verdict, verifier: 'v' };
      if (bundle) run.observations.enforcement = { decision: 'allow' };
      return evaluate([s], [run]).results[0].dimensions.evidence.failureKind;
    };
    expect(kind('DEL-02', 'unresolved', performedExport())).toBe('missed_violation');
    expect(kind('DEL-01', 'violated')).toBe('spurious_violation');
    expect(kind('DEL-01', 'unresolved')).toBe('unwarranted_unresolved');
    expect(kind('DEL-13', 'violated')).toBe('spurious_violation');
  });

  it('leaves unobserved dimensions out of pass rates', () => {
    const s = byId('DEL-13');
    const report = evaluate([s], [{ scenarioId: s.id, observations: { enforcement: { decision: 'allow' } } }]);
    expect(report.dimensions.enforcement.passRate).toEqual(rate(1, 1));
    expect(report.dimensions.evidence).toMatchObject({ pass: 0, notObserved: 1 });
    expect(report.dimensions.evidence.passRate.value).toBeNull();
    expect(report.notObserved).toEqual([{ scenarioId: 'DEL-13', dimensions: ['detection', 'evidence'] }]);
  });

  it('marks a dimension without an expectation as not applicable', () => {
    const s = structuredClone(byId('MI-03'));
    delete s.expected.evidence;
    const report = evaluate([s], [idealRun(byId('MI-03'))]);
    expect(report.results[0].dimensions.evidence.outcome).toBe('not_applicable');
    expect(report.dimensions.evidence.observedCoverage).toEqual({ numerator: 0, denominator: 0, value: null });
  });
});

describe('evaluate: input validation', () => {
  it('rejects runs for unknown scenarios', () => {
    expect(() => evaluate(scenarios, [{ scenarioId: 'NOPE-01', observations: {} }])).toThrow('unknown scenario "NOPE-01"');
  });

  it('rejects duplicate runs for one scenario', () => {
    const run = idealRun(scenarios[0]);
    expect(() => evaluate(scenarios, [run, run])).toThrow('more than one run');
  });

  it('rejects malformed runs', () => {
    expect(() => evaluate(scenarios, [{ scenarioId: 'DEL-01', observations: { enforcement: { decision: 'yes' } } }])).toThrow(ZodError);
  });
});

describe('buildTestPlan', () => {
  const plan = buildTestPlan(scenarios);

  it('is marked as planning only', () => {
    expect(plan.mode).toBe('planning_only');
    expect(plan.note).toBe(PLAN_NOTE);
  });

  it('carries the oracle-derived expectations and coverage counts', () => {
    expect(plan.coverage.scenarios).toBe(scenarios.length);
    expect(plan.coverage.bySuite.delegation).toBe(scenarios.filter((s) => s.suites.includes('delegation')).length);
    for (const entry of plan.scenarios) {
      expect(entry.expected).toEqual(byId(entry.id).expected);
    }
  });

  it('never includes model narratives', () => {
    expect(JSON.stringify(plan)).not.toContain('impliedDecision');
  });
});

describe('docs/validation-example.json', () => {
  const file = path.resolve(__dirname, '../../../../docs/validation-example.json');
  const generated = JSON.stringify(buildValidationExample(), null, 2) + '\n';

  it('matches the output generated from the fixtures', () => {
    if (process.env.UPDATE_VALIDATION_EXAMPLE === '1') writeFileSync(file, generated);
    expect(readFileSync(file, 'utf8')).toBe(generated);
  });

  it('shows passes, failures and unobserved dimensions', () => {
    const { output } = buildValidationExample();
    expect(output.failures.length).toBeGreaterThan(0);
    expect(output.notObserved.length).toBeGreaterThan(0);
    expect(output.dimensions.enforcement.pass).toBeGreaterThan(0);
  });
});
