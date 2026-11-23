import { describe, it, expect } from 'vitest';
import { AGENT_IDENTITY_SCENARIOS } from '@/data/validation/agent-identity-scenarios';
import { decide, expectedDetection, patternCovers, resourceMatches, verifyEvidence, type CheckCode } from '../policy';
import type { EvidenceBundle, ScenarioPolicy, SecurityScenario } from '../schema';

const scenario = (id: string): SecurityScenario => {
  const s = AGENT_IDENTITY_SCENARIOS.find((x) => x.id === id);
  if (!s) throw new Error(`no scenario ${id}`);
  return structuredClone(s);
};
const codes = (policy: ScenarioPolicy): CheckCode[] => decide(policy).failures.map((f) => f.code);
const valid = () => scenario('DEL-01');

describe('resource patterns', () => {
  it('matches prefix patterns and exact names only', () => {
    expect(resourceMatches('reports/*', 'reports/2025-Q3/a.pdf')).toBe(true);
    expect(resourceMatches('reports/*', 'reports-archive/a.pdf')).toBe(false);
    expect(resourceMatches('reports/a.pdf', 'reports/a.pdf')).toBe(true);
    expect(resourceMatches('reports/a.pdf', 'reports/a.pdf.bak')).toBe(false);
  });

  it('decides whether a parent pattern covers a child pattern', () => {
    expect(patternCovers('reports/*', 'reports/2025-Q3/*')).toBe(true);
    expect(patternCovers('reports/2025-Q3/*', 'reports/*')).toBe(false);
    expect(patternCovers('reports/a.pdf', 'reports/*')).toBe(false);
  });
});

describe('decide: delegation chain', () => {
  it('allows a valid narrowing chain', () => {
    expect(decide(valid().policy)).toEqual({ decision: 'allow', failures: [] });
  });

  it('never allows on identity alone', () => {
    const p = valid().policy;
    p.mandates = [];
    p.request.presentedProofs = [];
    expect(codes(p)).toEqual(['delegation.no_principal_mandate']);
  });

  it('rejects an origin mandate issued by an agent', () => {
    const p = valid().policy;
    p.mandates[0].issuer = { id: 'principal:finance-analyst', kind: 'agent' };
    expect(codes(p)).toContain('delegation.origin_not_principal');
  });

  it('rejects a request on behalf of a different principal', () => {
    const p = valid().policy;
    p.request.principalId = 'principal:someone-else';
    expect(codes(p)).toContain('delegation.principal_mismatch');
  });

  it('rejects a link that does not derive from its predecessor', () => {
    const p = valid().policy;
    p.mandates[1].parentId = undefined;
    expect(codes(p)).toContain('delegation.broken_chain');
  });

  it('rejects a delegation issued by an agent that does not hold the parent mandate', () => {
    const p = valid().policy;
    p.mandates[1].issuer = { id: 'agent:bystander', kind: 'agent' };
    expect(codes(p)).toEqual(['delegation.unauthorized_delegator']);
  });

  it('rejects a request from an agent that is not the final delegate', () => {
    const p = valid().policy;
    p.request.actor = 'agent:orchestrator';
    expect(codes(p)).toEqual(['delegation.actor_not_delegate']);
  });

  it('flags a child mandate that is broader than its parent even when the request is in scope', () => {
    const p = valid().policy;
    p.mandates[1].scope.resources = ['reports/2025-Q3/*', 'hr/*'];
    p.mandates[1].audience = ['tool:reports-api', 'tool:other'];
    const failures = decide(p).failures;
    expect(failures.map((f) => f.code)).toEqual(['delegation.link_exceeds_parent']);
    expect(failures[0].detail).toContain('resource hr/*');
    expect(failures[0].detail).toContain('audience tool:other');
  });

  it('enforces a tighter depth limit set by an intermediate mandate', () => {
    const p = scenario('DEL-05').policy;
    p.mandates[0].maxDelegationDepth = 5;
    p.mandates[1].maxDelegationDepth = 0;
    expect(codes(p)).toEqual(['delegation.depth_exceeded']);
    p.mandates[1].maxDelegationDepth = 1;
    expect(codes(p)).toEqual([]);
  });

  it('requires proof for every link at decision time', () => {
    const p = valid().policy;
    p.request.presentedProofs = ['m-origin'];
    expect(decide(p).failures).toEqual([{ code: 'delegation.unverifiable_link', detail: 'no proof presented for m-child' }]);
  });

  it('reports every widened dimension independently', () => {
    const p = valid().policy;
    Object.assign(p.request, { operation: 'delete', resource: 'hr/salaries.csv', purpose: 'training', audience: 'tool:x' });
    expect(codes(p).sort()).toEqual([
      'delegation.audience_outside_scope',
      'delegation.operation_outside_scope',
      'delegation.purpose_outside_scope',
      'delegation.resource_outside_scope',
    ]);
  });

  it('rejects a mandate that is not yet valid', () => {
    const p = valid().policy;
    p.mandates[1].notBefore = '2026-01-15T12:30:00.000Z';
    expect(codes(p)).toEqual(['delegation.not_yet_valid']);
  });

  it('treats expiry as exclusive at the exact commit instant', () => {
    const p = valid().policy;
    p.mandates[1].expiresAt = p.request.commitAt;
    expect(codes(p)).toEqual(['delegation.expired']);
  });
});

describe('decide: revocation and the commit boundary', () => {
  it('denies at commit when revocation happened after planning (TOCTOU)', () => {
    const p = scenario('DEL-12').policy;
    expect(codes(p)).toEqual(['delegation.revoked']);
    // The same request evaluated at planning time would have been allowed:
    const atPlanning = { ...p.request, commitAt: p.request.plannedAt! };
    expect(decide({ ...p, revocation: { ...p.revocation!, asOf: atPlanning.commitAt } }, atPlanning).decision).toBe('allow');
  });

  it('ignores a revocation that takes effect after the commit boundary', () => {
    const p = scenario('DEL-07').policy;
    p.revocation!.revoked[0].revokedAt = '2026-01-15T12:00:30.000Z';
    expect(codes(p)).toEqual([]);
  });

  it('fails closed on stale revocation status', () => {
    const p = scenario('DEL-07').policy;
    p.revocation!.revoked = [];
    p.revocation!.asOf = '2026-01-15T11:50:00.000Z';
    expect(codes(p)).toEqual(['revocation.status_stale']);
  });
});

describe('decide: identity, credentials, quotas, inputs and disclosure', () => {
  it('rejects an invalid signature and a mismatched subject', () => {
    const p = scenario('DID-03').policy;
    p.identity!.signatureValid = false;
    p.identity!.claimedAgentId = 'agent:someone-else';
    expect(codes(p).sort()).toEqual(['identity.invalid_signature', 'identity.subject_mismatch']);
  });

  it('accepts the current nonce once and rejects it once it is in the replay cache', () => {
    const p = scenario('VC-04').policy;
    expect(codes(p)).toEqual([]);
    p.presentation!.seenNonces.push(p.presentation!.nonce);
    expect(codes(p)).toEqual(['credential.replayed']);
  });

  it('counts actions across every agent of the principal', () => {
    const p = scenario('EPH-02').policy;
    p.quota!.priorActions = [{ agentId: 'agent:a', count: 9 }];
    expect(codes(p)).toEqual([]);
    p.quota!.priorActions.push({ agentId: 'agent:b', count: 1 });
    expect(codes(p)).toEqual(['quota.principal_limit_exceeded']);
  });

  it('reports both provenance and integrity failures', () => {
    const p = scenario('DP-03').policy;
    p.inputs![0] = { ...p.inputs![0], provenanceVerified: false, digestMatches: false };
    expect(codes(p).sort()).toEqual(['integrity.digest_mismatch', 'integrity.unverified_provenance']);
  });

  it('allows a protected artifact to an authorized caller but not over budget', () => {
    const p = scenario('MI-01').policy;
    p.disclosure!.callerAuthorizedForArtifact = true;
    expect(codes(p)).toEqual([]);
    p.disclosure!.queryCount = p.disclosure!.queryLimit + 1;
    expect(codes(p)).toEqual(['disclosure.query_budget_exceeded']);
  });

  it('expects an alert for untrusted instructions even when the action is allowed', () => {
    const p = scenario('PI-02').policy;
    expect(decide(p).decision).toBe('allow');
    expect(expectedDetection(p)).toBe('alert');
    p.request.initiatedBy = 'principal';
    expect(expectedDetection(p)).toBe('no_alert');
  });
});

describe('verifyEvidence', () => {
  const performed = (s: SecurityScenario): EvidenceBundle => structuredClone(s.evidence);

  it('preserves authority for an in-scope effect with complete evidence', () => {
    const s = valid();
    expect(verifyEvidence(s.policy, s.evidence)).toMatchObject({ verdict: 'preserved', missingEvidence: [] });
  });

  it('returns violated with the broken checks when an out-of-scope effect occurred', () => {
    const s = scenario('DEL-02');
    const bundle = performed(valid());
    if (bundle.effect.status !== 'performed') throw new Error('fixture');
    bundle.effect.operation = 'export';
    const result = verifyEvidence(s.policy, bundle);
    expect(result.verdict).toBe('violated');
    expect(result.violatedChecks).toEqual(['delegation.link_exceeds_parent', 'delegation.operation_outside_scope']);
  });

  it('returns violated for an effect with no mandate at all', () => {
    const s = scenario('DEL-08');
    const bundle = performed(valid());
    bundle.signedLinks = [];
    expect(verifyEvidence(s.policy, bundle).verdict).toBe('violated');
  });

  it('never treats a missing effect observation as preserved', () => {
    const s = valid();
    const bundle = performed(s);
    bundle.effect = { status: 'absent' };
    expect(verifyEvidence(s.policy, bundle)).toMatchObject({
      verdict: 'unresolved',
      findings: [{ code: 'evidence.no_effect_observation' }],
    });
  });

  it('does not accept the acting agent’s self-assertion', () => {
    const s = valid();
    const bundle = performed(s);
    bundle.effectSource = 'self_asserted';
    expect(verifyEvidence(s.policy, bundle).verdict).toBe('unresolved');
  });

  it('is unresolved when a link is unsigned, even for an effect that would be a violation', () => {
    const s = scenario('DEL-02');
    const bundle = performed(valid());
    if (bundle.effect.status !== 'performed') throw new Error('fixture');
    bundle.effect.operation = 'export';
    bundle.signedLinks = ['m-child'];
    const result = verifyEvidence(s.policy, bundle);
    expect(result.verdict).toBe('unresolved');
    expect(result.missingEvidence).toEqual(['signed delegation link for mandate m-origin']);
  });

  it('is unresolved without a decision record, or with one recorded after the effect', () => {
    const s = valid();
    const noRecord = performed(s);
    delete noRecord.decisionRecord;
    expect(verifyEvidence(s.policy, noRecord).findings.map((f) => f.code)).toEqual(['evidence.missing_decision_record']);

    const late = performed(s);
    late.decisionRecord = { decision: 'allow', recordedAt: '2026-01-15T12:05:00.000Z' };
    expect(verifyEvidence(s.policy, late)).toMatchObject({ verdict: 'unresolved', findings: [{ code: 'evidence.decision_after_effect' }] });
  });

  it('evaluates an effect at the time it occurred, not at the planned commit', () => {
    const s = valid();
    const bundle = performed(s);
    if (bundle.effect.status !== 'performed') throw new Error('fixture');
    bundle.effect.at = '2026-01-15T14:30:00.000Z'; // after the child mandate expired
    bundle.decisionRecord = { decision: 'allow', recordedAt: '2026-01-15T12:00:00.000Z' };
    const result = verifyEvidence(s.policy, bundle);
    expect(result.verdict).toBe('violated');
    expect(result.violatedChecks).toEqual(['delegation.expired']);
  });

  it('checks conflicts first', () => {
    const s = scenario('DEL-10');
    const result = verifyEvidence(s.policy, s.evidence);
    expect(result.findings.map((f) => f.code)).toEqual(['evidence.conflicting_records']);
  });
});
