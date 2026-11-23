/**
 * Threat-to-control mapping for agent identity and delegation threats.
 *
 * The seven families, their MAESTRO layers and the summary mitigations follow
 * Table 5 ("MAESTRO Security Threat Assessment for Multi-Agent Systems") of the
 * CSA publication "Agentic AI Identity and Access Management: A New Approach"
 * (released 2025-08-18). Descriptions are paraphrased. The control objectives,
 * evidence lists and scenarios built on them are proposals of this module and
 * are not part of, or endorsed by, that publication.
 */
import type { MaestroLayer, ScenarioRegistry, ThreatFamily } from '@/lib/validation/schema';

export interface SourceReference {
  title: string;
  publisher: string;
  date?: string;
  url?: string;
  note?: string;
}

export const SOURCES = {
  'csa-agentic-iam-2025': {
    title: 'Agentic AI Identity and Access Management: A New Approach',
    publisher: 'Cloud Security Alliance',
    date: '2025-08-18',
    url: 'https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach',
    note: 'Table 5: MAESTRO Security Threat Assessment for Multi-Agent Systems. Threat rows, layers and mitigations are paraphrased.',
  },
  'csa-maestro-2025': {
    title: 'Agentic AI Threat Modeling Framework: MAESTRO',
    publisher: 'Cloud Security Alliance',
    date: '2025-02-06',
    url: 'https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro',
  },
  'w3c-did-core': {
    title: 'Decentralized Identifiers (DIDs) v1.0',
    publisher: 'W3C',
    url: 'https://www.w3.org/TR/did-core/',
  },
  'w3c-vc-data-model-2': {
    title: 'Verifiable Credentials Data Model v2.0',
    publisher: 'W3C',
    url: 'https://www.w3.org/TR/vc-data-model-2.0/',
  },
  'module-delegation-cases': {
    title: 'Delegation boundary cases defined for this validation module',
    publisher: 'MAESTRO threat-to-control validation module',
    note: 'Test cases written for this module. They refine Table 5 row 4 and are not taken from a CSA publication.',
  },
} as const satisfies Record<string, SourceReference>;
export type SourceId = keyof typeof SOURCES;

export interface ControlObjective {
  name: string;
  objective: string;
}

export const CONTROLS = {
  'CTL-ID-01': {
    name: 'Identity-to-key binding',
    objective: 'Accept an agent identity only when the presented key is bound to the claimed identifier by an integrity-protected identity document.',
  },
  'CTL-ID-02': {
    name: 'Issuer and resolver trust',
    objective: 'Resolve identity documents only through pinned, trusted resolvers or issuers.',
  },
  'CTL-CR-01': {
    name: 'Challenge nonce binding',
    objective: 'Require each credential presentation to carry the verifier’s current challenge nonce.',
  },
  'CTL-CR-02': {
    name: 'Replay detection',
    objective: 'Reject any presentation whose nonce has already been accepted.',
  },
  'CTL-CR-03': {
    name: 'Audience binding',
    objective: 'Reject a presentation at any service other than the audience it is bound to.',
  },
  'CTL-CR-04': {
    name: 'Credential lifetime',
    objective: 'Reject presentations that have expired at the time of use.',
  },
  'CTL-DG-01': {
    name: 'Scope intersection',
    objective: 'Authorize only operations, resources, purposes and audiences granted by every mandate in the chain.',
  },
  'CTL-DG-02': {
    name: 'Authorized delegation path',
    objective: 'Require an unbroken chain from a principal’s mandate in which each delegator holds the parent mandate and no link widens it.',
  },
  'CTL-DG-03': {
    name: 'Re-delegation depth limit',
    objective: 'Enforce the maximum number of re-delegations each mandate permits.',
  },
  'CTL-DG-04': {
    name: 'Commit-boundary authorization',
    objective: 'Evaluate validity, expiry and revocation when the action takes effect, not when it was planned.',
  },
  'CTL-DG-05': {
    name: 'Revocation freshness',
    objective: 'Fail closed when revocation status is older than the permitted maximum age.',
  },
  'CTL-DG-06': {
    name: 'Principal mandate required',
    objective: 'Never authorize on agent identity alone; require a mandate from the principal.',
  },
  'CTL-EP-01': {
    name: 'Principal-bound aggregate limits',
    objective: 'Count actions against the principal across all of its agents, including short-lived ones.',
  },
  'CTL-EP-02': {
    name: 'Agent lifecycle correlation',
    objective: 'Attribute every spawned agent to the principal and parent that created it.',
  },
  'CTL-PI-01': {
    name: 'Context-independent policy enforcement',
    objective: 'Make authorization decisions from policy and mandates only, never from instructions in model context.',
  },
  'CTL-PI-02': {
    name: 'Instruction source classification',
    objective: 'Label instructions that originate in tool output or retrieved content as untrusted and flag them.',
  },
  'CTL-DP-01': {
    name: 'Input provenance verification',
    objective: 'Use data in a security decision only when its source has been verified.',
  },
  'CTL-DP-02': {
    name: 'Input integrity verification',
    objective: 'Use data in a security decision only when its digest matches the published value.',
  },
  'CTL-MI-01': {
    name: 'Protected artifact access restriction',
    objective: 'Deny queries that would return model weights, system prompts or secrets to unauthorized callers.',
  },
  'CTL-MI-02': {
    name: 'Extraction rate limiting',
    objective: 'Limit query volume per caller and window to bound extraction attempts.',
  },
  'CTL-EV-01': {
    name: 'Independent effect observation',
    objective: 'Record whether the action took effect from a source other than the acting agent.',
  },
  'CTL-EV-02': {
    name: 'Signed delegation evidence',
    objective: 'Retain a verifiable signed link for every mandate in the chain.',
  },
  'CTL-EV-03': {
    name: 'Authoritative record reconciliation',
    objective: 'Designate which record is authoritative when logs disagree.',
  },
} as const satisfies Record<string, ControlObjective>;
export type ControlId = keyof typeof CONTROLS;

export interface ThreatFamilyMapping {
  /** Row number in Table 5 of the source publication. */
  table5Row: number;
  name: string;
  /** Paraphrase of the Table 5 description. */
  description: string;
  maestroLayers: readonly MaestroLayer[];
  /** Paraphrase of the Table 5 recommended mitigation. */
  sourceMitigation: string;
  /** Control objectives proposed by this module. */
  controls: readonly ControlId[];
  evidenceNeeded: readonly string[];
  /**
   * What the evidence dimension is about for this family. Only `authority`
   * families are questions of delegated authority; the others use the same
   * verdict vocabulary for integrity or disclosure evidence.
   */
  evidenceKind: 'authority' | 'integrity' | 'disclosure';
}

export const THREAT_FAMILIES: Record<ThreatFamily, ThreatFamilyMapping> = {
  did_spoofing: {
    table5Row: 1,
    name: 'DID spoofing / impersonation',
    description: 'A forged or manipulated identity document is used to pass as a privileged agent.',
    maestroLayers: ['agent-frameworks', 'security-compliance', 'agent-ecosystem'],
    sourceMitigation: 'Pin resolvers and validate identity document signatures.',
    controls: ['CTL-ID-01', 'CTL-ID-02', 'CTL-DG-06'],
    evidenceNeeded: ['verified identity-to-key binding', 'issuer or resolver trust decision', 'principal mandate'],
    evidenceKind: 'authority',
  },
  vc_replay: {
    table5Row: 2,
    name: 'Verifiable credential replay',
    description: 'A captured credential is reused to gain privileges.',
    maestroLayers: ['agent-frameworks', 'security-compliance'],
    sourceMitigation: 'Bind credentials to a nonce and limit their lifetime.',
    controls: ['CTL-CR-01', 'CTL-CR-02', 'CTL-CR-03', 'CTL-CR-04'],
    evidenceNeeded: ['presented nonce and issued challenge', 'replay cache decision', 'audience and expiry of the presentation'],
    evidenceKind: 'authority',
  },
  ephemeral_agent_abuse: {
    table5Row: 3,
    name: 'Ephemeral agent abuse',
    description: 'Many short-lived agents are spawned to exhaust resources or hide malicious activity.',
    maestroLayers: ['agent-frameworks', 'deployment-infrastructure', 'agent-ecosystem'],
    sourceMitigation: 'Rate limiting, anomaly detection and revocation.',
    controls: ['CTL-EP-01', 'CTL-EP-02', 'CTL-DG-01'],
    evidenceNeeded: ['per-principal action count across agents', 'agent-to-principal lifecycle trace'],
    evidenceKind: 'authority',
  },
  delegation_escalation: {
    table5Row: 4,
    name: 'Delegation escalation',
    description: 'Delegations are chained so that an agent ends up with more privilege than its principal granted.',
    maestroLayers: ['agent-frameworks', 'security-compliance', 'agent-ecosystem'],
    sourceMitigation: 'Scope delegations and limit re-delegation chains.',
    controls: ['CTL-DG-01', 'CTL-DG-02', 'CTL-DG-03', 'CTL-DG-04', 'CTL-DG-05', 'CTL-DG-06', 'CTL-EV-01', 'CTL-EV-02', 'CTL-EV-03'],
    evidenceNeeded: [
      'origin mandate from the principal',
      'every intermediate delegation, signed',
      'effective scope at the commit boundary',
      'the requested action',
      'independent evidence of what was executed',
    ],
    evidenceKind: 'authority',
  },
  prompt_injection: {
    table5Row: 5,
    name: 'Prompt injection',
    description: 'Crafted input to a foundation model causes harmful or unintended agent behaviour.',
    maestroLayers: ['foundation-models', 'agent-frameworks', 'security-compliance'],
    sourceMitigation: 'Input validation and prompt moderation or guardrails.',
    controls: ['CTL-PI-01', 'CTL-PI-02', 'CTL-DG-01'],
    evidenceNeeded: ['classification of the instruction source', 'policy decision for the resulting action'],
    evidenceKind: 'authority',
  },
  data_poisoning: {
    table5Row: 6,
    name: 'Data poisoning',
    description: 'Malicious or corrupted data enters a dataset or pipeline the agent relies on.',
    maestroLayers: ['data-operations', 'security-compliance'],
    sourceMitigation: 'Verify dataset integrity and detect anomalies in the data pipeline.',
    controls: ['CTL-DP-01', 'CTL-DP-02'],
    evidenceNeeded: ['provenance record for each input', 'integrity (digest) check result', 'detection status'],
    evidenceKind: 'integrity',
  },
  model_inversion: {
    table5Row: 7,
    name: 'Model inversion / extraction',
    description: 'Queries are used to extract model intellectual property or embedded secrets.',
    maestroLayers: ['foundation-models', 'deployment-infrastructure', 'security-compliance'],
    sourceMitigation: 'Encrypt model artifacts at rest and restrict access to model-retrieval APIs.',
    controls: ['CTL-MI-01', 'CTL-MI-02'],
    evidenceNeeded: ['query trace for the caller and window', 'measured disclosure for the response'],
    evidenceKind: 'disclosure',
  },
};

export const SCENARIO_REGISTRY: ScenarioRegistry = {
  controls: new Set(Object.keys(CONTROLS)),
  sources: new Set(Object.keys(SOURCES)),
  familyLayers: Object.fromEntries(
    Object.entries(THREAT_FAMILIES).map(([family, mapping]) => [family, mapping.maestroLayers]),
  ) as ScenarioRegistry['familyLayers'],
};
