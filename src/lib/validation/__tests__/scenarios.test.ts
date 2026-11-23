import { describe, it, expect } from 'vitest';
import { AGENT_IDENTITY_SCENARIOS } from '@/data/validation/agent-identity-scenarios';
import { CONTROLS, SCENARIO_REGISTRY, SOURCES, THREAT_FAMILIES } from '@/data/validation/threat-control-map';
import { MAESTRO_LAYERS } from '@/data/maestro';
import { deriveExpectation } from '../evaluate';
import { decide, verifyEvidence } from '../policy';
import { THREAT_FAMILY_IDS, parseScenarioSuite } from '../schema';

const scenarios = AGENT_IDENTITY_SCENARIOS;

describe('agent identity scenario fixtures', () => {
  it('parse against the schema and the control/source/layer registry', () => {
    expect(() => parseScenarioSuite(scenarios, SCENARIO_REGISTRY)).not.toThrow();
  });

  it('contain between 20 and 30 scenarios covering all seven threat families', () => {
    expect(scenarios.length).toBeGreaterThanOrEqual(20);
    expect(scenarios.length).toBeLessThanOrEqual(30);
    const families = new Set(scenarios.map((s) => s.threatFamily));
    expect([...families].sort()).toEqual([...THREAT_FAMILY_IDS].sort());
  });

  it('contain at least 12 delegation-suite cases', () => {
    const delegation = scenarios.filter((s) => s.suites.includes('delegation'));
    expect(delegation.length).toBeGreaterThanOrEqual(12);
  });

  it('include a valid negative control (expected allow) in every family', () => {
    for (const family of THREAT_FAMILY_IDS) {
      const controls = scenarios.filter((s) => s.threatFamily === family && s.expected.enforcement === 'allow');
      expect(controls.length, family).toBeGreaterThanOrEqual(1);
    }
  });

  it('include unresolved evidence cases that are not counted as preserved', () => {
    const unresolved = scenarios.filter((s) => s.expected.evidence === 'unresolved').map((s) => s.id);
    expect(unresolved).toEqual(expect.arrayContaining(['DEL-09', 'DEL-10', 'DEL-13']));
  });

  describe.each(scenarios.map((s) => [s.id, s] as const))('%s', (_id, scenario) => {
    const derived = deriveExpectation(scenario);

    it('declares the enforcement decision the oracle derives', () => {
      expect(scenario.expected.enforcement).toBe(derived.enforcement);
    });

    it('declares the detection expectation the oracle derives', () => {
      expect(scenario.expected.detection).toBe(derived.detection);
    });

    it('declares the evidence verdict the reference verifier derives', () => {
      expect(scenario.expected.evidence).toBe(derived.evidence);
    });

    it('lists exactly the denial reasons the oracle reports', () => {
      expect([...derived.reasons].sort()).toEqual([...scenario.expectedReasons].sort());
    });
  });
});

describe('model narratives are never used as ground truth', () => {
  const withNarrative = scenarios.filter((s) => s.modelNarrative);

  it('at least three scenarios carry a narrative that contradicts the oracle', () => {
    expect(withNarrative.length).toBeGreaterThanOrEqual(3);
    for (const s of withNarrative) {
      expect(s.modelNarrative!.impliedDecision, s.id).not.toBe(deriveExpectation(s).enforcement);
    }
  });

  it('removing or inverting the narrative does not change any derived outcome', () => {
    for (const s of withNarrative) {
      const baseline = deriveExpectation(s);
      const removed = deriveExpectation({ ...s, modelNarrative: undefined });
      const inverted = deriveExpectation({
        ...s,
        modelNarrative: { text: 'The opposite conclusion.', impliedDecision: baseline.enforcement },
      });
      expect(removed).toEqual(baseline);
      expect(inverted).toEqual(baseline);
    }
  });
});

describe('threat-to-control map', () => {
  it('maps Table 5 rows 1 to 7 once each', () => {
    const rows = Object.values(THREAT_FAMILIES).map((f) => f.table5Row).sort();
    expect(rows).toEqual([1, 2, 3, 4, 5, 6, 7]);
  });

  it('uses canonical MAESTRO layer ids and known controls', () => {
    const layerIds = new Set<string>(MAESTRO_LAYERS.map((l) => l.id));
    for (const family of Object.values(THREAT_FAMILIES)) {
      for (const layer of family.maestroLayers) expect(layerIds.has(layer)).toBe(true);
      for (const control of family.controls) expect(control in CONTROLS).toBe(true);
    }
  });

  it('marks only identity and authorization families as authority evidence', () => {
    expect(THREAT_FAMILIES.data_poisoning.evidenceKind).toBe('integrity');
    expect(THREAT_FAMILIES.model_inversion.evidenceKind).toBe('disclosure');
    expect(THREAT_FAMILIES.delegation_escalation.evidenceKind).toBe('authority');
  });

  it('cites the CSA publication without claiming the module-defined cases come from it', () => {
    expect(SOURCES['csa-agentic-iam-2025'].url).toContain('cloudsecurityalliance.org');
    expect(SOURCES['module-delegation-cases'].note).toMatch(/not taken from a CSA publication/);
  });
});

describe('fixture hygiene', () => {
  const serialized = JSON.stringify(scenarios);

  it('contain no credentials, private keys or live endpoints', () => {
    expect(serialized).not.toMatch(/-----BEGIN [A-Z ]*PRIVATE KEY-----/);
    expect(serialized).not.toMatch(/\b(sk-[A-Za-z0-9]{10,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,})\b/);
    expect(serialized).not.toMatch(/https?:\/\//);
  });

  it('use only reserved example domains for identity resolvers', () => {
    const domains = serialized.match(/did:web:[a-z0-9.-]+/g) ?? [];
    for (const d of domains) expect(d).toMatch(/\.example(\.com)?$/);
  });

  it('are independent of the wall clock', () => {
    const before = scenarios.map((s) => [decide(s.policy), verifyEvidence(s.policy, s.evidence)]);
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2099-01-01T00:00:00Z'));
    try {
      const after = scenarios.map((s) => [decide(s.policy), verifyEvidence(s.policy, s.evidence)]);
      expect(after).toEqual(before);
    } finally {
      vi.useRealTimers();
    }
  });
});
