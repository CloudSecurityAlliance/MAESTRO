# Threat-to-control validation

This module adds a deterministic way to say what a control should do about a
MAESTRO threat, and to check observations of a real system against that
statement. It complements the Threat Analyzer's model-generated threats and
mitigations. It does not replace them and does not change them.

The module is a standalone TypeScript library with Vitest tests. It has no UI,
calls no model, opens no network connection and needs no API key.

- Schemas: [`src/lib/validation/schema.ts`](../src/lib/validation/schema.ts)
- Reference oracle and evidence verifier: [`src/lib/validation/policy.ts`](../src/lib/validation/policy.ts)
- Evaluation and test plans: [`src/lib/validation/evaluate.ts`](../src/lib/validation/evaluate.ts)
- Threat-to-control map: [`src/data/validation/threat-control-map.ts`](../src/data/validation/threat-control-map.ts)
- Scenarios: [`src/data/validation/agent-identity-scenarios.ts`](../src/data/validation/agent-identity-scenarios.ts)
- Worked example: [`docs/validation-example.json`](validation-example.json), built by [`src/data/validation/example.ts`](../src/data/validation/example.ts)

## Planning, not execution

The module produces and checks **test plans and fixtures**. It does not run
attacks, drive agents, or connect to the system under test. Someone running a
scenario against a real system records what they saw as a `ScenarioRun`, and
`evaluate` compares those observations with the scenario's expectations.

A passing report means the supplied observations matched the listed
scenarios. It is not a certification, it does not show production
conformance, and dimensions that were not observed are never counted as
passes.

## Three dimensions, scored separately

| Dimension | Question | Expected values |
| --- | --- | --- |
| `enforcement` | Did the system prevent the prohibited action, and allow the valid one? | `allow` or `deny` |
| `detection` | Did the system flag the attempt? | `alert` or `no_alert` |
| `evidence` | Can an independent verifier establish that the effect stayed within delegated authority? | `preserved`, `violated` or `unresolved` |

A system can pass one and fail another. Scenario PI-02 is an example: an
instruction injected through tool output asks for an action the agent's
mandate already allows, so enforcement should **allow** it while detection
should still **alert**. There is no combined score.

For each scenario and dimension the outcome is one of `pass`, `fail`,
`not_observed` (no observation supplied) or `not_applicable` (the scenario
sets no expectation for that dimension).

`unresolved` is a verdict in its own right. It is never treated as `preserved`.
An allow decision is not evidence that an action stayed in scope, the acting
agent's own record of what it did is not independent evidence, and the absence
of a log entry is not evidence that nothing happened.

## Threat-to-control map

The seven threat families, their MAESTRO layers and the summary mitigations
follow Table 5, "MAESTRO Security Threat Assessment for Multi-Agent Systems",
of the CSA publication *Agentic AI Identity and Access Management: A New
Approach* (released 18 August 2025). Descriptions here are paraphrased. The
control objectives, evidence lists and scenarios are proposals of this module;
they are not part of that publication and are not endorsed by CSA.

| Table 5 row | Family | MAESTRO layers | Controls modelled | Evidence needed | Evidence kind |
| --- | --- | --- | --- | --- | --- |
| 1 | DID spoofing / impersonation | agent-frameworks, security-compliance, agent-ecosystem | key binding (CTL-ID-01), resolver trust (CTL-ID-02), principal mandate (CTL-DG-06) | verified key binding, trust decision | authority |
| 2 | VC replay | agent-frameworks, security-compliance | nonce (CTL-CR-01), replay cache (CTL-CR-02), audience (CTL-CR-03), expiry (CTL-CR-04) | presented nonce and challenge, replay decision, audience and expiry | authority |
| 3 | Ephemeral agent abuse | agent-frameworks, deployment-infrastructure, agent-ecosystem | principal-bound limits (CTL-EP-01), lifecycle correlation (CTL-EP-02) | per-principal count across agents, lifecycle trace | authority |
| 4 | Delegation escalation | agent-frameworks, security-compliance, agent-ecosystem | scope intersection, delegation path, depth limit, commit-boundary checks, revocation freshness (CTL-DG-01 to 06), evidence controls (CTL-EV-01 to 03) | origin mandate, every signed delegation, effective scope at commit, requested action, independent execution evidence | authority |
| 5 | Prompt injection | foundation-models, agent-frameworks, security-compliance | context-independent enforcement (CTL-PI-01), source classification (CTL-PI-02) | instruction source, policy decision | authority |
| 6 | Data poisoning | data-operations, security-compliance | provenance (CTL-DP-01), integrity (CTL-DP-02) | provenance and digest records, detection status | integrity |
| 7 | Model inversion / extraction | foundation-models, deployment-infrastructure, security-compliance | protected-artifact access (CTL-MI-01), query budget (CTL-MI-02) | query trace, measured disclosure | disclosure |

"Evidence kind" records that only some families are questions of delegated
authority. Data poisoning and model inversion use the same verdict words, but
their evidence concerns input integrity and disclosure, and they are kept as
separate tests rather than treated as authorization checks.

Layer ids are the ones in [`src/data/maestro.ts`](../src/data/maestro.ts).
`parseScenarioSuite` rejects a scenario whose layers are not mapped to its
family.

## Scenarios

There are 30 scenarios: 13 in the delegation escalation family, plus 3 DID,
4 VC replay, 2 ephemeral agent, 2 prompt injection, 3 data poisoning and 3
model inversion. Every family has at least one valid negative control that a
correct system must allow; blocking it counts against the false-positive
blocking rate.

The delegation sub-suite (`suites: ['delegation']`) has 16 cases:

| Id | Case | Enforcement | Evidence |
| --- | --- | --- | --- |
| DEL-01 | Valid narrowing delegation | allow | preserved |
| DEL-02 | Child mandate widens the operation (read → export) | deny | preserved |
| DEL-03 | Request widens the resource (Q3 reports → all customer data) | deny | preserved |
| DEL-04 | Request widens the purpose (summarization → marketing) | deny | preserved |
| DEL-05 | Re-delegation beyond the permitted depth | deny | preserved |
| DEL-06 | Mandate expired before the commit boundary | deny | preserved |
| DEL-07 | Revoked mandate, signed token still present | deny | preserved |
| DEL-08 | Valid identity, no principal mandate | deny | preserved |
| DEL-09 | Missing signed ancestor link | deny | **unresolved** |
| DEL-10 | Conflicting records of the effective scope | allow | **unresolved** |
| DEL-11 | Authorized in-scope action (negative control) | allow | preserved |
| DEL-12 | Revocation between planning and execution (TOCTOU) | deny | preserved |
| DEL-13 | Allowed decision without execution evidence | allow | **unresolved** |
| VC-03 | Presentation for one tool replayed to another | deny | preserved |
| PI-01 | Tool output instructs a scope expansion | deny | preserved |
| EPH-01 | Short-lived agents share one principal limit | deny | preserved |

For denied cases the reference evidence shows the action independently
observed **not** to happen, so the verdict is `preserved`. If a run supplies
evidence that the prohibited action did happen, the same scenario evaluates
to `violated` and enforcement fails (see the DEL-02 run in the worked
example). DEL-09 is denied correctly and still `unresolved`: the protective
deny does not make the missing link appear.

All identifiers are fictional (`example.com`, `agent:report-writer`, ...).
Fixtures contain no keys, secrets or URLs, and times are fixed constants; a
test asserts that results do not change when the clock does.

## How expectations are derived

Each scenario has three parts:

- `policy` holds the authoritative facts: the mandate chain from the
  principal to the acting agent, the request, and any identity proof,
  credential presentation, revocation status, principal quota, input
  integrity records or disclosure classification.
- `evidence` is the reference evidence bundle a correct system would leave.
- `expected` and `expectedReasons` are declared by hand.

`decide(policy)` derives allow or deny from `policy` alone. `verifyEvidence`
derives the evidence verdict from `policy` and an evidence bundle. The test
suite checks every scenario's declared expectations against these functions,
so a hand label cannot drift from the rules.

Some scenarios also carry a `modelNarrative`: an illustrative, model-style
statement that reaches the wrong conclusion (for example, "the agent presented
a valid DID, so it is authorized"). The oracle never reads it. Tests check
that each narrative disagrees with the oracle and that removing or inverting it
changes nothing.

### Decision rules

`decide` denies if any check fails and reports every failed check with a code:

- **Identity:** signature valid, presented key bound to the claimed id,
  issuer trusted, identity matches the actor.
- **Credential presentation:** nonce equals the issued challenge, nonce not
  already accepted, audience equals the target, not expired at commit.
- **Delegation:** a principal mandate exists (identity alone is never
  authority); the origin is issued by the request's principal; each link
  derives from its parent and is issued by the parent's subject; no link
  claims more than its parent; the chain ends at the actor; no mandate's
  depth limit is exceeded; proof was presented for every link; operation,
  resource, purpose and audience are granted by **every** link (scope
  intersection); every link is valid and unexpired **at commit time**; no link
  is revoked at or before commit; revocation status is no older than its
  maximum age (fail closed).
- **Principal quota:** actions across all of the principal's agents in the
  window, plus this one, must not exceed the limit.
- **Inputs:** every input used for the decision has verified provenance and a
  matching digest.
- **Disclosure:** protected artifacts only to authorized callers; query count
  within budget.

The detection expectation is `alert` when the request is denied, or when it
was initiated by untrusted content, and `no_alert` otherwise.

### Evidence verdict rules

`verifyEvidence` applies these in order:

1. Irreconcilable records → `unresolved`
2. Effect recorded only by the acting agent → `unresolved`
3. A mandate in the chain without a signed link → `unresolved`
4. No observation of the effect → `unresolved`
5. Effect independently observed not to happen → `preserved`
6. Effect outside the authority, evaluated at the time it happened → `violated`
7. No decision record, or one recorded after the effect → `unresolved`
8. Otherwise → `preserved`

Each `unresolved` result lists the evidence that would resolve it.

## Evaluating a system

```ts
import { AGENT_IDENTITY_SCENARIOS } from '@/data/validation/agent-identity-scenarios';
import { evaluate } from '@/lib/validation';

const report = evaluate(AGENT_IDENTITY_SCENARIOS, [
  {
    scenarioId: 'DEL-02',
    observations: {
      enforcement: { decision: 'deny' },
      detection: { alerted: true },
      evidence: { verdict: 'preserved', verifier: 'my-verifier' },
    },
    // Optional: the evidence the system actually produced. When present, the
    // reference verdict is computed from it instead of the scenario's bundle.
    // evidenceBundle: { ... },
  },
]);
```

Runs are validated with `ScenarioRunSchema`. A run for an unknown scenario, or
two runs for one scenario, is an error. Scenarios without a run are reported as
not observed.

The report contains:

- per-dimension counts and rates, each as `{ numerator, denominator, value }`
  (`value` is `null` when the denominator is 0);
- the same per threat family and for the delegation suite;
- `falsePositiveBlocking`: valid scenarios the system denied, over valid
  scenarios with an observed decision;
- `failures`: scenario id, dimension, failure kind, expected and observed
  values, the policy checks involved and any missing evidence;
- `notObserved`: which dimensions of which scenarios had no observation.

Failure kinds are `false_allow`, `false_deny` (over-blocking),
`enforcement_bypass` (reported deny, effect happened anyway),
`missed_detection`, `false_alert`, `overclaimed_authority` (claimed
`preserved` without grounds), `missed_violation`, `spurious_violation` and
`unwarranted_unresolved`.

`buildTestPlan(scenarios)` returns a planning-only document with each
scenario's derived expectations, controls, evidence requirements, assumptions
and limitations. It never includes model narratives.

## Running the tests and the example

```bash
npx vitest run src/lib/validation
```

[`docs/validation-example.json`](validation-example.json) holds six
illustrative runs from a fictional system and the report produced from them.
A test fails if the file differs from what the code generates. To regenerate
it after changing scenarios:

```bash
UPDATE_VALIDATION_EXAMPLE=1 npx vitest run src/lib/validation
```

## External evidence verifiers

`AuthorityEvidenceVerifier` in `schema.ts` is a vendor-neutral interface for a
verifier of some specific evidence format. An adapter's verdict goes into a
run's `observations.evidence`, and `evaluate` checks it against the reference
verifier. No adapter ships with this module, and none is needed to run it.

One candidate for a later, optional adapter is AMEP (Agentic Mandate Evidence
Protocol, <https://github.com/stafordtituss/amep>), an independent open-source
specification by the contributor of this module, also published as an
individual IETF Internet-Draft
([draft-stafordtituss-agentic-mandate-evidence](https://datatracker.ietf.org/doc/draft-stafordtituss-agentic-mandate-evidence/)).
An individual draft is a work in progress, not an IETF standard, and AMEP is
not a CSA-endorsed protocol. AMEP uses the same three verdict words. Its
schemas, verifiers and conformance vectors are not copied into this
repository.

## Adding scenarios

1. Add the scenario to `agent-identity-scenarios.ts`, or to a new file in
   `src/data/validation/` exported the same way. Use an id like `DEL-14`.
2. Use only controls in `CONTROLS`, sources in `SOURCES`, and layers mapped
   to the family in `THREAT_FAMILIES`. Add a source entry for any new
   reference, and mark cases you wrote yourself as such rather than
   attributing them to a publication.
3. Set `expected` and `expectedReasons` to what you believe is correct, then
   run the tests. If the oracle disagrees, decide whether the fixture or the
   rule is wrong; do not change one to match the other without a reason.
4. Include a negative control for any new family.
5. Keep fixtures fictional: no real keys, tokens, hostnames or user data.

New kinds of check belong in `policy.ts` with a new code in `CHECK_CODES`, a
unit test in `__tests__/policy.test.ts`, and at least one scenario that
exercises it.

## Limitations

- The oracle checks the facts in the fixture. It cannot tell whether a real
  system's purpose declarations, input classifications or disclosure
  classifications are truthful; those are supplied by the fixture.
- Resource matching supports exact names and `prefix/*` patterns only.
- Purpose enforcement assumes the policy encodes purpose and the request
  declares it.
- Ephemeral-agent scenarios assume each agent is already attributed to its
  principal; they test the aggregate limit, not the attribution.
- Data-integrity checks do not detect poisoning by a legitimate but
  compromised publisher.
- Model inversion scenarios test access and budget rules, not measured
  information leakage.
- The delegation sub-suite refines Table 5 row 4, and EPH-01 extends row 3
  from resource exhaustion to aggregate-limit evasion. These cases are
  defined by this module (source `module-delegation-cases`), not by the
  publication.

## Provenance

The module was written independently by Staford Titus Selvaraj (GitHub
@stafordtituss), a co-author of the CSA publication cited above. It is a
proposal for this repository, and its inclusion would not imply CSA
endorsement of the module's control objectives or of any external protocol.
