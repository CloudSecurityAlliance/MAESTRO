/**
 * Schemas for MAESTRO threat-to-control validation scenarios.
 *
 * A scenario has three separate parts:
 *  - `policy`: the authoritative, fixture-defined facts (mandates, request,
 *    credentials, quotas, ...). The reference oracle in `policy.ts` derives
 *    the correct decision from these facts alone.
 *  - `evidence`: the reference evidence bundle a correctly behaving system
 *    would leave behind. The reference verifier derives the evidence verdict
 *    from it.
 *  - `expected`: the outcomes the fixture author declares. Tests check that
 *    they agree with what the oracle derives, so a hand label can never
 *    silently disagree with the policy.
 *
 * Observations of a system under test live in a separate `ScenarioRun`.
 */
import { z } from 'zod';
import { MAESTRO_LAYERS } from '@/data/maestro';

type MaestroLayerId = (typeof MAESTRO_LAYERS)[number]['id'];

export const MaestroLayerIdSchema = z.enum(
  MAESTRO_LAYERS.map((layer) => layer.id) as [MaestroLayerId, ...MaestroLayerId[]],
);

export const THREAT_FAMILY_IDS = [
  'did_spoofing',
  'vc_replay',
  'ephemeral_agent_abuse',
  'delegation_escalation',
  'prompt_injection',
  'data_poisoning',
  'model_inversion',
] as const;
export const ThreatFamilySchema = z.enum(THREAT_FAMILY_IDS);

export const DIMENSIONS = ['detection', 'enforcement', 'evidence'] as const;
export const DimensionSchema = z.enum(DIMENSIONS);

/** Result of comparing one dimension of a run with the expectation. */
export const ObservationSchema = z.enum(['pass', 'fail', 'not_observed', 'not_applicable']);

export const AuthorityVerdictSchema = z.enum(['preserved', 'violated', 'unresolved']);
export const DecisionSchema = z.enum(['allow', 'deny']);
export const DetectionExpectationSchema = z.enum(['alert', 'no_alert']);

export const SUITE_IDS = ['delegation'] as const;
export const SuiteSchema = z.enum(SUITE_IDS);

const IsoTimestamp = z.string().datetime({ offset: true });
const NonEmpty = z.string().trim().min(1);
const NonEmptyList = z.array(NonEmpty).min(1);

const time = (iso: string): number => Date.parse(iso);

// ---------------------------------------------------------------------------
// Authoritative policy facts
// ---------------------------------------------------------------------------

export const ScopeSchema = z
  .object({
    operations: NonEmptyList,
    /** Exact resource names, or a prefix pattern ending in `/*`. */
    resources: NonEmptyList,
    purposes: NonEmptyList,
  })
  .strict();

export const MandateSchema = z
  .object({
    id: NonEmpty,
    /** Id of the mandate this one was delegated from. Absent on the origin mandate. */
    parentId: NonEmpty.optional(),
    issuer: z.object({ id: NonEmpty, kind: z.enum(['principal', 'agent']) }).strict(),
    /** Agent the authority is granted to. */
    subject: NonEmpty,
    scope: ScopeSchema,
    /** Tools or services the authority may be exercised against. */
    audience: NonEmptyList,
    notBefore: IsoTimestamp,
    expiresAt: IsoTimestamp,
    /** Maximum number of further delegation hops below this mandate. */
    maxDelegationDepth: z.number().int().min(0).optional(),
  })
  .strict()
  .refine((m) => time(m.expiresAt) > time(m.notBefore), {
    message: 'expiresAt must be later than notBefore',
    path: ['expiresAt'],
  });

export const ActionRequestSchema = z
  .object({
    actor: NonEmpty,
    principalId: NonEmpty,
    operation: NonEmpty,
    resource: NonEmpty,
    purpose: NonEmpty,
    /** Tool or service the action is directed at. */
    audience: NonEmpty,
    /** When the agent planned the action, if different from the commit time. */
    plannedAt: IsoTimestamp.optional(),
    /** The commit boundary: when the action would take effect. */
    commitAt: IsoTimestamp,
    /** Where the instruction that produced this request came from. */
    initiatedBy: z.enum(['principal', 'agent', 'untrusted_content']),
    /** Mandate ids for which verifiable proof was presented at decision time. */
    presentedProofs: z.array(NonEmpty),
  })
  .strict()
  .refine((r) => r.plannedAt === undefined || time(r.plannedAt) <= time(r.commitAt), {
    message: 'plannedAt must not be later than commitAt',
    path: ['plannedAt'],
  });

export const IdentityProofSchema = z
  .object({
    claimedAgentId: NonEmpty,
    presentedKeyId: NonEmpty,
    /** Key ids bound to the claimed identifier by the resolved identity document. */
    boundKeyIds: z.array(NonEmpty),
    /** Issuer or resolver of the identity document. */
    issuer: NonEmpty,
    trustedIssuers: z.array(NonEmpty),
    signatureValid: z.boolean(),
  })
  .strict();

export const CredentialPresentationSchema = z
  .object({
    credentialId: NonEmpty,
    nonce: NonEmpty,
    /** Challenge nonce the verifier issued for this interaction. */
    expectedNonce: NonEmpty,
    /** Audience the presentation is bound to. */
    audience: NonEmpty,
    expiresAt: IsoTimestamp,
    /** Nonces already accepted by the verifier (replay cache). */
    seenNonces: z.array(NonEmpty),
  })
  .strict();

export const RevocationStatusSchema = z
  .object({
    /** When the revocation status was last fetched. */
    asOf: IsoTimestamp,
    /** Maximum acceptable age of the status at the commit boundary. */
    maxAgeSeconds: z.number().int().positive(),
    revoked: z.array(z.object({ mandateId: NonEmpty, revokedAt: IsoTimestamp }).strict()),
  })
  .strict();

export const PrincipalQuotaSchema = z
  .object({
    principalId: NonEmpty,
    windowStart: IsoTimestamp,
    windowEnd: IsoTimestamp,
    /** Maximum actions per principal in the window, across all agents. */
    limit: z.number().int().positive(),
    /** Actions already taken in the window, per agent. */
    priorActions: z.array(z.object({ agentId: NonEmpty, count: z.number().int().min(0) }).strict()),
  })
  .strict()
  .refine((q) => time(q.windowEnd) > time(q.windowStart), {
    message: 'windowEnd must be later than windowStart',
    path: ['windowEnd'],
  });

export const InputRecordSchema = z
  .object({
    id: NonEmpty,
    source: NonEmpty,
    provenanceVerified: z.boolean(),
    digestMatches: z.boolean(),
  })
  .strict();

export const DisclosureSchema = z
  .object({
    /** Classification of what the query would return, supplied by the authoritative policy. */
    artifactClass: z.enum(['public_output', 'protected_model_artifact', 'secret']),
    callerAuthorizedForArtifact: z.boolean(),
    /** Queries in the current window, including this one. */
    queryCount: z.number().int().min(1),
    queryLimit: z.number().int().positive(),
  })
  .strict();

export const ScenarioPolicySchema = z
  .object({
    /** Mandate chain ordered from the principal's origin mandate to the acting agent. May be empty. */
    mandates: z.array(MandateSchema),
    request: ActionRequestSchema,
    identity: IdentityProofSchema.optional(),
    presentation: CredentialPresentationSchema.optional(),
    revocation: RevocationStatusSchema.optional(),
    quota: PrincipalQuotaSchema.optional(),
    inputs: z.array(InputRecordSchema).min(1).optional(),
    disclosure: DisclosureSchema.optional(),
  })
  .strict()
  .superRefine((policy, ctx) => {
    const ids = policy.mandates.map((m) => m.id);
    const known = new Set(ids);
    if (known.size !== ids.length) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['mandates'], message: 'mandate ids must be unique' });
    }
    policy.mandates.forEach((m, i) => {
      if (m.parentId !== undefined && !known.has(m.parentId)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['mandates', i, 'parentId'],
          message: `parentId "${m.parentId}" does not reference a mandate in this policy`,
        });
      }
      if (m.parentId === m.id) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['mandates', i, 'parentId'], message: 'a mandate cannot be its own parent' });
      }
    });
    policy.request.presentedProofs.forEach((id, i) => {
      if (!known.has(id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['request', 'presentedProofs', i],
          message: `presented proof "${id}" does not reference a mandate in this policy`,
        });
      }
    });
    policy.revocation?.revoked.forEach((entry, i) => {
      if (!known.has(entry.mandateId)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['revocation', 'revoked', i, 'mandateId'],
          message: `revoked mandate "${entry.mandateId}" does not reference a mandate in this policy`,
        });
      }
    });
    if (policy.quota) {
      const q = policy.quota;
      if (q.principalId !== policy.request.principalId) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['quota', 'principalId'], message: 'quota principal must match the request principal' });
      }
      const commit = time(policy.request.commitAt);
      if (commit < time(q.windowStart) || commit >= time(q.windowEnd)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['quota'], message: 'request commitAt must fall inside the quota window' });
      }
    }
  });

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

export const EffectSchema = z.discriminatedUnion('status', [
  z
    .object({
      status: z.literal('performed'),
      operation: NonEmpty,
      resource: NonEmpty,
      purpose: NonEmpty,
      audience: NonEmpty,
      at: IsoTimestamp,
    })
    .strict(),
  z.object({ status: z.literal('not_performed'), observedAt: IsoTimestamp }).strict(),
  /** No observation of the effect exists. Never read as "nothing happened". */
  z.object({ status: z.literal('absent') }).strict(),
]);

export const EvidenceBundleSchema = z
  .object({
    /** Mandate ids for which a verifiable signed delegation link is in evidence. */
    signedLinks: z.array(NonEmpty),
    decisionRecord: z.object({ decision: DecisionSchema, recordedAt: IsoTimestamp }).strict().optional(),
    effect: EffectSchema,
    /** `self_asserted`: the only record of the effect comes from the acting agent. */
    effectSource: z.enum(['independent', 'self_asserted']),
    /** Records that disagree and cannot be reconciled by an authoritative rule. */
    conflicts: z.array(NonEmpty),
  })
  .strict();

// ---------------------------------------------------------------------------
// Scenario
// ---------------------------------------------------------------------------

export const ExpectedOutcomeSchema = z
  .object({
    enforcement: DecisionSchema.optional(),
    detection: DetectionExpectationSchema.optional(),
    evidence: AuthorityVerdictSchema.optional(),
  })
  .strict()
  .refine((e) => e.enforcement !== undefined || e.detection !== undefined || e.evidence !== undefined, {
    message: 'at least one dimension must have an expectation',
  });

export const ModelNarrativeSchema = z
  .object({
    /** Illustrative model-style narrative. Never an input to the oracle. */
    text: NonEmpty,
    impliedDecision: DecisionSchema,
  })
  .strict();

export const SecurityScenarioSchema = z
  .object({
    id: z.string().regex(/^[A-Z]{2,4}-\d{2}$/, 'id must look like DEL-01'),
    title: NonEmpty,
    threatFamily: ThreatFamilySchema,
    suites: z.array(SuiteSchema),
    maestroLayers: z.array(MaestroLayerIdSchema).min(1),
    assumptions: NonEmptyList,
    setup: NonEmpty,
    attemptedBehavior: NonEmpty,
    policy: ScenarioPolicySchema,
    evidence: EvidenceBundleSchema,
    expected: ExpectedOutcomeSchema,
    /** Check codes the oracle must report for this scenario (all of them, in any order). */
    expectedReasons: z.array(NonEmpty),
    evidenceRequired: NonEmptyList,
    controls: NonEmptyList,
    sources: NonEmptyList,
    limitations: z.array(NonEmpty).optional(),
    modelNarrative: ModelNarrativeSchema.optional(),
  })
  .strict()
  .superRefine((s, ctx) => {
    const known = new Set(s.policy.mandates.map((m) => m.id));
    s.evidence.signedLinks.forEach((id, i) => {
      if (!known.has(id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['evidence', 'signedLinks', i],
          message: `signed link "${id}" does not reference a mandate in this scenario's policy`,
        });
      }
    });
    if (s.expected.enforcement === 'allow' && s.expectedReasons.length > 0) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['expectedReasons'], message: 'an allowed scenario cannot list denial reasons' });
    }
    if (s.expected.enforcement === 'deny' && s.expectedReasons.length === 0) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['expectedReasons'], message: 'a denied scenario must list at least one denial reason' });
    }
  });

export const ScenarioRunSchema = z
  .object({
    scenarioId: NonEmpty,
    /** Free-form label for the system under test. */
    system: NonEmpty.optional(),
    observations: z
      .object({
        enforcement: z.object({ decision: DecisionSchema }).strict().optional(),
        detection: z.object({ alerted: z.boolean() }).strict().optional(),
        evidence: z.object({ verdict: AuthorityVerdictSchema, verifier: NonEmpty }).strict().optional(),
      })
      .strict(),
    /** Evidence the system under test actually produced. Replaces the scenario's reference bundle. */
    evidenceBundle: EvidenceBundleSchema.optional(),
    notes: z.array(NonEmpty).optional(),
  })
  .strict();

export type Dimension = z.infer<typeof DimensionSchema>;
export type Observation = z.infer<typeof ObservationSchema>;
export type AuthorityVerdict = z.infer<typeof AuthorityVerdictSchema>;
export type Decision = z.infer<typeof DecisionSchema>;
export type DetectionExpectation = z.infer<typeof DetectionExpectationSchema>;
export type ThreatFamily = z.infer<typeof ThreatFamilySchema>;
export type Suite = z.infer<typeof SuiteSchema>;
export type MaestroLayer = z.infer<typeof MaestroLayerIdSchema>;
export type Mandate = z.infer<typeof MandateSchema>;
export type ActionRequest = z.infer<typeof ActionRequestSchema>;
export type ScenarioPolicy = z.infer<typeof ScenarioPolicySchema>;
export type Effect = z.infer<typeof EffectSchema>;
export type EvidenceBundle = z.infer<typeof EvidenceBundleSchema>;
export type ExpectedOutcome = z.infer<typeof ExpectedOutcomeSchema>;
export type SecurityScenario = z.infer<typeof SecurityScenarioSchema>;
export type ScenarioRun = z.infer<typeof ScenarioRunSchema>;

/**
 * Vendor-neutral interface for an independent authority-evidence verifier.
 *
 * An adapter for a specific evidence format implements this and its verdict is
 * recorded as `observations.evidence` on a `ScenarioRun`. No adapter ships with
 * this module; the reference verifier in `policy.ts` is used to check adapters.
 */
export interface AuthorityEvidenceVerifier {
  readonly name: string;
  verify(input: { scenarioId: string; evidence: unknown }): Promise<{
    verdict: AuthorityVerdict;
    reasons: string[];
  }>;
}

export interface ScenarioRegistry {
  controls: ReadonlySet<string>;
  sources: ReadonlySet<string>;
  /** MAESTRO layers each family is mapped to; a scenario's layers must be a subset. */
  familyLayers: Readonly<Record<ThreatFamily, readonly MaestroLayer[]>>;
}

/**
 * Parse a list of scenarios and check cross-references against a registry.
 * Throws a `z.ZodError` describing every problem found.
 */
export function parseScenarioSuite(input: unknown, registry: ScenarioRegistry): SecurityScenario[] {
  return z
    .array(SecurityScenarioSchema)
    .min(1)
    .superRefine((scenarios, ctx) => {
      const seen = new Set<string>();
      scenarios.forEach((s, i) => {
        if (seen.has(s.id)) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, path: [i, 'id'], message: `duplicate scenario id "${s.id}"` });
        }
        seen.add(s.id);
        s.controls.forEach((c, j) => {
          if (!registry.controls.has(c)) {
            ctx.addIssue({ code: z.ZodIssueCode.custom, path: [i, 'controls', j], message: `unknown control "${c}"` });
          }
        });
        s.sources.forEach((src, j) => {
          if (!registry.sources.has(src)) {
            ctx.addIssue({ code: z.ZodIssueCode.custom, path: [i, 'sources', j], message: `unknown source "${src}"` });
          }
        });
        const allowed = new Set(registry.familyLayers[s.threatFamily]);
        s.maestroLayers.forEach((layer, j) => {
          if (!allowed.has(layer)) {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              path: [i, 'maestroLayers', j],
              message: `layer "${layer}" is not mapped to threat family "${s.threatFamily}"`,
            });
          }
        });
      });
    })
    .parse(input);
}
