import { describe, it, expect } from 'vitest';
import { ZodError } from 'zod';
import { AGENT_IDENTITY_SCENARIOS } from '@/data/validation/agent-identity-scenarios';
import { SCENARIO_REGISTRY } from '@/data/validation/threat-control-map';
import { ScenarioRunSchema, SecurityScenarioSchema, parseScenarioSuite } from '../schema';

// Work on plain JSON so malformed values can be injected without type casts.
type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const base = (id = 'DEL-01'): Json => JSON.parse(JSON.stringify(AGENT_IDENTITY_SCENARIOS.find((s) => s.id === id)));

const issues = (input: unknown): string[] => {
  const result = SecurityScenarioSchema.safeParse(input);
  if (result.success) return [];
  return result.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`);
};

describe('SecurityScenarioSchema rejects malformed scenarios', () => {
  it('accepts an unmodified fixture', () => {
    expect(issues(base())).toEqual([]);
  });

  it('rejects an unknown threat family', () => {
    const s = base();
    s.threatFamily = 'quantum_spoofing';
    expect(issues(s).some((m) => m.startsWith('threatFamily'))).toBe(true);
  });

  it('rejects a MAESTRO layer id that does not exist', () => {
    const s = base();
    s.maestroLayers = ['layer-8'];
    expect(issues(s).some((m) => m.startsWith('maestroLayers.0'))).toBe(true);
  });

  it('rejects unknown fields', () => {
    const s = base();
    s.policy.request.grantAll = true;
    expect(issues(s).some((m) => m.includes('Unrecognized key'))).toBe(true);
  });

  it('rejects a mandate that expires before it starts', () => {
    const s = base();
    s.policy.mandates[1].expiresAt = s.policy.mandates[1].notBefore;
    expect(issues(s)).toContain('policy.mandates.1.expiresAt: expiresAt must be later than notBefore');
  });

  it('rejects a dangling parent reference', () => {
    const s = base();
    s.policy.mandates[1].parentId = 'm-ghost';
    expect(issues(s)).toContain('policy.mandates.1.parentId: parentId "m-ghost" does not reference a mandate in this policy');
  });

  it('rejects duplicate mandate ids', () => {
    const s = base();
    s.policy.mandates[1].id = 'm-origin';
    s.policy.mandates[1].parentId = 'm-origin';
    expect(issues(s)).toContain('policy.mandates: mandate ids must be unique');
  });

  it('rejects proofs, signed links and revocations for mandates that do not exist', () => {
    const s = base();
    s.policy.request.presentedProofs.push('m-ghost');
    s.evidence.signedLinks.push('m-ghost');
    s.policy.revocation = { asOf: '2026-01-15T12:00:00.000Z', maxAgeSeconds: 60, revoked: [{ mandateId: 'm-ghost', revokedAt: '2026-01-15T11:00:00.000Z' }] };
    const found = issues(s);
    expect(found.some((m) => m.startsWith('policy.request.presentedProofs.2'))).toBe(true);
    expect(found.some((m) => m.startsWith('evidence.signedLinks.2'))).toBe(true);
    expect(found.some((m) => m.startsWith('policy.revocation.revoked.0.mandateId'))).toBe(true);
  });

  it('rejects planning after commit', () => {
    const s = base();
    s.policy.request.plannedAt = '2026-01-15T13:00:00.000Z';
    expect(issues(s)).toContain('policy.request.plannedAt: plannedAt must not be later than commitAt');
  });

  it('rejects a quota for another principal or a commit outside its window', () => {
    const s = base('EPH-01');
    s.policy.quota.principalId = 'principal:other';
    s.policy.quota.windowEnd = '2026-01-15T11:59:00.000Z';
    const found = issues(s);
    expect(found).toContain('policy.quota.principalId: quota principal must match the request principal');
    expect(found).toContain('policy.quota: request commitAt must fall inside the quota window');
  });

  it('rejects a performed effect without its action details, and details on a non-performed effect', () => {
    const s = base();
    delete s.evidence.effect.operation;
    expect(issues(s).some((m) => m.startsWith('evidence.effect.operation'))).toBe(true);

    const t = base();
    t.evidence.effect = { status: 'not_performed', observedAt: '2026-01-15T12:00:05.000Z', operation: 'read' };
    expect(issues(t).some((m) => m.includes('Unrecognized key'))).toBe(true);
  });

  it('rejects impossible expectations', () => {
    const allowWithReasons = base();
    allowWithReasons.expectedReasons = ['delegation.expired'];
    expect(issues(allowWithReasons)).toContain('expectedReasons: an allowed scenario cannot list denial reasons');

    const denyWithout = base('DEL-02');
    denyWithout.expectedReasons = [];
    expect(issues(denyWithout)).toContain('expectedReasons: a denied scenario must list at least one denial reason');

    const empty = base();
    empty.expected = {};
    expect(issues(empty)).toContain('expected: at least one dimension must have an expectation');

    const badVerdict = base();
    badVerdict.expected.evidence = 'probably_fine';
    expect(issues(badVerdict).some((m) => m.startsWith('expected.evidence'))).toBe(true);
  });

  it('requires evidence requirements, controls and sources', () => {
    const s = base();
    s.evidenceRequired = [];
    s.controls = [];
    s.sources = [];
    const found = issues(s);
    expect(found.some((m) => m.startsWith('evidenceRequired'))).toBe(true);
    expect(found.some((m) => m.startsWith('controls'))).toBe(true);
    expect(found.some((m) => m.startsWith('sources'))).toBe(true);
  });
});

describe('parseScenarioSuite', () => {
  const messages = (input: unknown): string[] => {
    try {
      parseScenarioSuite(input, SCENARIO_REGISTRY);
      return [];
    } catch (e) {
      expect(e).toBeInstanceOf(ZodError);
      return (e as ZodError).issues.map((i) => i.message);
    }
  };

  it('rejects duplicate scenario ids', () => {
    expect(messages([base(), base()])).toContain('duplicate scenario id "DEL-01"');
  });

  it('rejects unknown controls and sources', () => {
    const s = base();
    s.controls = ['CTL-NOPE-01'];
    s.sources = ['a-blog-post'];
    expect(messages([s])).toEqual(expect.arrayContaining(['unknown control "CTL-NOPE-01"', 'unknown source "a-blog-post"']));
  });

  it('rejects a layer that Table 5 does not map to the family', () => {
    const s = base('DP-01');
    s.maestroLayers = ['agent-ecosystem'];
    expect(messages([s])).toContain('layer "agent-ecosystem" is not mapped to threat family "data_poisoning"');
  });

  it('rejects an empty suite', () => {
    expect(messages([]).length).toBeGreaterThan(0);
  });
});

describe('ScenarioRunSchema', () => {
  it('accepts a run with only some dimensions observed', () => {
    expect(ScenarioRunSchema.safeParse({ scenarioId: 'DEL-01', observations: { enforcement: { decision: 'deny' } } }).success).toBe(true);
  });

  it('rejects unknown observation values and unknown dimensions', () => {
    expect(ScenarioRunSchema.safeParse({ scenarioId: 'DEL-01', observations: { enforcement: { decision: 'maybe' } } }).success).toBe(false);
    expect(ScenarioRunSchema.safeParse({ scenarioId: 'DEL-01', observations: { safety: { score: 1 } } }).success).toBe(false);
    expect(
      ScenarioRunSchema.safeParse({ scenarioId: 'DEL-01', observations: { evidence: { verdict: 'preserved' } } }).success,
    ).toBe(false); // verifier name is required
  });
});
