/**
 * Deterministic evaluation of observed runs against validation scenarios.
 *
 * Each dimension (detection, enforcement, evidence) is scored on its own, with
 * explicit denominators. A dimension with no observation is `not_observed` and
 * is never counted as a pass. There is no combined score.
 */
import { decide, effectAsRequest, expectedDetection, verifyEvidence, type CheckCode } from './policy';
import {
  DIMENSIONS,
  SUITE_IDS,
  THREAT_FAMILY_IDS,
  ScenarioRunSchema,
  type AuthorityVerdict,
  type Decision,
  type DetectionExpectation,
  type Dimension,
  type Observation,
  type ScenarioRun,
  type SecurityScenario,
  type Suite,
  type ThreatFamily,
} from './schema';

export const REPORT_DISCLAIMER =
  'Results describe only the listed scenarios and the observations supplied for them. ' +
  'They are not a security certification, do not establish production conformance, ' +
  'and unobserved dimensions are not counted as passes.';

export const PLAN_NOTE =
  'This is a test plan. It states what a control should do for each scenario; ' +
  'it does not execute, contact, or measure any system.';

export interface DerivedExpectation {
  enforcement: Decision;
  detection: DetectionExpectation;
  evidence: AuthorityVerdict;
  reasons: CheckCode[];
  missingEvidence: string[];
}

/** Derive a scenario's expected outcomes from its policy and reference evidence alone. */
export function deriveExpectation(scenario: SecurityScenario): DerivedExpectation {
  const decision = decide(scenario.policy);
  const verification = verifyEvidence(scenario.policy, scenario.evidence);
  return {
    enforcement: decision.decision,
    detection: expectedDetection(scenario.policy, decision),
    evidence: verification.verdict,
    reasons: decision.failures.map((f) => f.code),
    missingEvidence: verification.missingEvidence,
  };
}

export type FailureKind =
  | 'false_allow'
  | 'false_deny'
  | 'enforcement_bypass'
  | 'missed_detection'
  | 'false_alert'
  | 'overclaimed_authority'
  | 'missed_violation'
  | 'spurious_violation'
  | 'unwarranted_unresolved';

export interface DimensionResult {
  outcome: Observation;
  expected: string | null;
  observed: string | null;
  failureKind?: FailureKind;
  detail?: string;
}

export interface ScenarioResult {
  scenarioId: string;
  title: string;
  threatFamily: ThreatFamily;
  suites: Suite[];
  dimensions: Record<Dimension, DimensionResult>;
  /** Policy checks that make the scenario's request (or observed effect) unauthorized. */
  failedChecks: CheckCode[];
  /** Evidence the reference verifier needed and did not find. */
  missingEvidence: string[];
}

export interface Failure {
  scenarioId: string;
  dimension: Dimension;
  failureKind: FailureKind;
  expected: string;
  observed: string;
  detail: string;
  failedChecks: CheckCode[];
  missingEvidence: string[];
}

export interface Rate {
  numerator: number;
  denominator: number;
  /** `numerator / denominator`, rounded to 4 places; `null` when the denominator is 0. */
  value: number | null;
}

export interface DimensionSummary {
  total: number;
  pass: number;
  fail: number;
  notObserved: number;
  notApplicable: number;
  /** pass / (pass + fail). */
  passRate: Rate;
  /** (pass + fail) / (total - notApplicable). */
  observedCoverage: Rate;
}

export interface GroupSummary {
  scenarios: number;
  dimensions: Record<Dimension, DimensionSummary>;
}

export interface ValidationReport {
  kind: 'maestro.threat-control-validation.report';
  version: 1;
  system: string | null;
  scenarioCount: number;
  runCount: number;
  dimensions: Record<Dimension, DimensionSummary>;
  byFamily: Record<ThreatFamily, GroupSummary>;
  bySuite: Record<Suite, GroupSummary>;
  /** Valid (expected-allow) scenarios the system blocked, over those with an observed decision. */
  falsePositiveBlocking: Rate;
  failures: Failure[];
  notObserved: { scenarioId: string; dimensions: Dimension[] }[];
  results: ScenarioResult[];
  disclaimer: string;
}

export function rate(numerator: number, denominator: number): Rate {
  return {
    numerator,
    denominator,
    value: denominator === 0 ? null : Math.round((numerator / denominator) * 10000) / 10000,
  };
}

const notApplicable = (): DimensionResult => ({ outcome: 'not_applicable', expected: null, observed: null });

function evaluateEnforcement(scenario: SecurityScenario, run: ScenarioRun | undefined): DimensionResult {
  const expected = scenario.expected.enforcement;
  if (expected === undefined) return notApplicable();
  const decision = run?.observations.enforcement?.decision;
  const effect = run?.evidenceBundle?.effect;

  // An unauthorized effect that actually happened is a failure whatever the system reported.
  if (expected === 'deny' && effect?.status === 'performed') {
    const effectCheck = decide(scenario.policy, effectAsRequest(scenario.policy, effect));
    if (effectCheck.decision === 'deny') {
      return {
        outcome: 'fail',
        expected,
        observed: `${decision ?? 'decision not observed'}; effect performed`,
        failureKind: decision === 'allow' ? 'false_allow' : 'enforcement_bypass',
        detail: `the prohibited action (${effect.operation} on ${effect.resource}) took effect at ${effect.at}`,
      };
    }
  }

  if (decision === undefined) return { outcome: 'not_observed', expected, observed: null };
  if (decision === expected) return { outcome: 'pass', expected, observed: decision };
  return {
    outcome: 'fail',
    expected,
    observed: decision,
    failureKind: expected === 'deny' ? 'false_allow' : 'false_deny',
    detail:
      expected === 'deny'
        ? 'the system allowed a request the authoritative policy denies'
        : 'the system blocked a request the authoritative policy allows (over-blocking)',
  };
}

function evaluateDetection(scenario: SecurityScenario, run: ScenarioRun | undefined): DimensionResult {
  const expected = scenario.expected.detection;
  if (expected === undefined) return notApplicable();
  const alerted = run?.observations.detection?.alerted;
  if (alerted === undefined) return { outcome: 'not_observed', expected, observed: null };
  const observed = alerted ? 'alert' : 'no_alert';
  if (observed === expected) return { outcome: 'pass', expected, observed };
  return {
    outcome: 'fail',
    expected,
    observed,
    failureKind: expected === 'alert' ? 'missed_detection' : 'false_alert',
    detail: expected === 'alert' ? 'the attempt was not flagged' : 'a valid request was flagged',
  };
}

function evidenceFailureKind(observed: AuthorityVerdict, reference: AuthorityVerdict): FailureKind {
  if (observed === 'preserved') return 'overclaimed_authority';
  if (observed === 'violated') return 'spurious_violation';
  return reference === 'violated' ? 'missed_violation' : 'unwarranted_unresolved';
}

function evaluateEvidence(
  scenario: SecurityScenario,
  run: ScenarioRun | undefined,
): { result: DimensionResult; missingEvidence: string[]; violatedChecks: CheckCode[] } {
  if (scenario.expected.evidence === undefined) {
    return { result: notApplicable(), missingEvidence: [], violatedChecks: [] };
  }
  // The reference verdict is computed over whatever evidence the run actually produced.
  const reference = verifyEvidence(scenario.policy, run?.evidenceBundle ?? scenario.evidence);
  const base = { missingEvidence: reference.missingEvidence, violatedChecks: reference.violatedChecks };
  const observed = run?.observations.evidence?.verdict;
  if (observed === undefined) {
    return { result: { outcome: 'not_observed', expected: reference.verdict, observed: null }, ...base };
  }
  if (observed === reference.verdict) {
    return { result: { outcome: 'pass', expected: reference.verdict, observed }, ...base };
  }
  return {
    result: {
      outcome: 'fail',
      expected: reference.verdict,
      observed,
      failureKind: evidenceFailureKind(observed, reference.verdict),
      detail: reference.findings.map((f) => `${f.code}: ${f.detail}`).join('; '),
    },
    ...base,
  };
}

function emptySummary(): DimensionSummary {
  return { total: 0, pass: 0, fail: 0, notObserved: 0, notApplicable: 0, passRate: rate(0, 0), observedCoverage: rate(0, 0) };
}

function summarize(results: ScenarioResult[]): Record<Dimension, DimensionSummary> {
  const out = {} as Record<Dimension, DimensionSummary>;
  for (const dim of DIMENSIONS) {
    const s = emptySummary();
    for (const r of results) {
      s.total++;
      const outcome = r.dimensions[dim].outcome;
      if (outcome === 'pass') s.pass++;
      else if (outcome === 'fail') s.fail++;
      else if (outcome === 'not_observed') s.notObserved++;
      else s.notApplicable++;
    }
    s.passRate = rate(s.pass, s.pass + s.fail);
    s.observedCoverage = rate(s.pass + s.fail, s.total - s.notApplicable);
    out[dim] = s;
  }
  return out;
}

function indexRuns(scenarios: SecurityScenario[], rawRuns: unknown[]): Map<string, ScenarioRun> {
  const ids = new Set(scenarios.map((s) => s.id));
  const runs = new Map<string, ScenarioRun>();
  for (const raw of rawRuns) {
    const run = ScenarioRunSchema.parse(raw);
    if (!ids.has(run.scenarioId)) {
      throw new Error(`run references unknown scenario "${run.scenarioId}"`);
    }
    if (runs.has(run.scenarioId)) {
      throw new Error(`more than one run for scenario "${run.scenarioId}"`);
    }
    runs.set(run.scenarioId, run);
  }
  return runs;
}

/**
 * Evaluate observed runs against scenarios. Runs are validated with
 * `ScenarioRunSchema`; scenarios without a run are reported as not observed.
 */
export function evaluate(
  scenarios: SecurityScenario[],
  runs: unknown[],
  options: { system?: string } = {},
): ValidationReport {
  const byId = indexRuns(scenarios, runs);
  const results: ScenarioResult[] = [];
  const failures: Failure[] = [];
  const notObserved: ValidationReport['notObserved'] = [];
  let falseBlocks = 0;
  let validWithDecision = 0;

  for (const scenario of scenarios) {
    const run = byId.get(scenario.id);
    const enforcement = evaluateEnforcement(scenario, run);
    const detection = evaluateDetection(scenario, run);
    const evidence = evaluateEvidence(scenario, run);
    const failedChecks = [
      ...new Set([...decide(scenario.policy).failures.map((f) => f.code), ...evidence.violatedChecks]),
    ];
    const result: ScenarioResult = {
      scenarioId: scenario.id,
      title: scenario.title,
      threatFamily: scenario.threatFamily,
      suites: scenario.suites,
      dimensions: { detection, enforcement, evidence: evidence.result },
      failedChecks,
      missingEvidence: evidence.missingEvidence,
    };
    results.push(result);

    const unobserved: Dimension[] = [];
    for (const dim of DIMENSIONS) {
      const d = result.dimensions[dim];
      if (d.outcome === 'not_observed') unobserved.push(dim);
      if (d.outcome === 'fail' && d.failureKind) {
        failures.push({
          scenarioId: scenario.id,
          dimension: dim,
          failureKind: d.failureKind,
          expected: d.expected ?? '',
          observed: d.observed ?? '',
          detail: d.detail ?? '',
          failedChecks,
          missingEvidence: dim === 'evidence' ? evidence.missingEvidence : [],
        });
      }
    }
    if (unobserved.length > 0) notObserved.push({ scenarioId: scenario.id, dimensions: unobserved });

    if (scenario.expected.enforcement === 'allow' && run?.observations.enforcement) {
      validWithDecision++;
      if (run.observations.enforcement.decision === 'deny') falseBlocks++;
    }
  }

  const group = (filter: (r: ScenarioResult) => boolean): GroupSummary => {
    const subset = results.filter(filter);
    return { scenarios: subset.length, dimensions: summarize(subset) };
  };
  const byFamily = Object.fromEntries(
    THREAT_FAMILY_IDS.map((f) => [f, group((r) => r.threatFamily === f)]),
  ) as Record<ThreatFamily, GroupSummary>;
  const bySuite = Object.fromEntries(
    SUITE_IDS.map((s) => [s, group((r) => r.suites.includes(s))]),
  ) as Record<Suite, GroupSummary>;

  return {
    kind: 'maestro.threat-control-validation.report',
    version: 1,
    system: options.system ?? null,
    scenarioCount: scenarios.length,
    runCount: byId.size,
    dimensions: summarize(results),
    byFamily,
    bySuite,
    falsePositiveBlocking: rate(falseBlocks, validWithDecision),
    failures,
    notObserved,
    results,
    disclaimer: REPORT_DISCLAIMER,
  };
}

export interface TestPlan {
  kind: 'maestro.threat-control-validation.plan';
  version: 1;
  mode: 'planning_only';
  note: string;
  coverage: {
    scenarios: number;
    byFamily: Record<ThreatFamily, number>;
    bySuite: Record<Suite, number>;
  };
  scenarios: {
    id: string;
    title: string;
    threatFamily: ThreatFamily;
    suites: Suite[];
    maestroLayers: string[];
    setup: string;
    attemptedBehavior: string;
    expected: { enforcement: Decision; detection: DetectionExpectation; evidence: AuthorityVerdict };
    denialReasons: CheckCode[];
    evidenceRequired: string[];
    controls: string[];
    sources: string[];
    assumptions: string[];
    limitations: string[];
  }[];
}

/** Build a planning-only description of what each scenario expects, derived by the oracle. */
export function buildTestPlan(scenarios: SecurityScenario[]): TestPlan {
  const count = <K extends string>(keys: readonly K[], match: (s: SecurityScenario, k: K) => boolean) =>
    Object.fromEntries(keys.map((k) => [k, scenarios.filter((s) => match(s, k)).length])) as Record<K, number>;
  return {
    kind: 'maestro.threat-control-validation.plan',
    version: 1,
    mode: 'planning_only',
    note: PLAN_NOTE,
    coverage: {
      scenarios: scenarios.length,
      byFamily: count(THREAT_FAMILY_IDS, (s, f) => s.threatFamily === f),
      bySuite: count(SUITE_IDS, (s, k) => s.suites.includes(k)),
    },
    scenarios: scenarios.map((s) => {
      const derived = deriveExpectation(s);
      return {
        id: s.id,
        title: s.title,
        threatFamily: s.threatFamily,
        suites: s.suites,
        maestroLayers: s.maestroLayers,
        setup: s.setup,
        attemptedBehavior: s.attemptedBehavior,
        expected: { enforcement: derived.enforcement, detection: derived.detection, evidence: derived.evidence },
        denialReasons: derived.reasons,
        evidenceRequired: s.evidenceRequired,
        controls: s.controls,
        sources: s.sources,
        assumptions: s.assumptions,
        limitations: s.limitations ?? [],
      };
    }),
  };
}
