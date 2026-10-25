# Internal Risk Scoring — Module 9 (Phase 09)

> Code: `backend/app/services/risk.py`. Exposed read-only via `GET /api/risk-formula`. Shown on every finding's detail page (`frontend/src/pages/FindingDetailPage.tsx`) as a labelled breakdown, never silently baked into the stored `Finding`.

This is **not CVSS** and is never labelled as CVSS. It is a transparent, code-level internal prioritization aid that combines signals the project already has honest data for, so triage does not rest on any single tool's severity label alone (MASTER_SPEC §9).

## 1. Inputs and weights

| Signal | Source | Weight |
|---|---|---|
| Severity | `Finding.severity` (scanner/import-reported, never altered by scoring) | Critical 100, High 75, Medium 50, Low 25, Informational 5 |
| Confidence | `Finding.confidence` | Confirmed ×1.0, Probable ×0.8, Potential ×0.55, Needs review ×0.35 |
| Asset criticality | Highest `Asset.criticality` among the finding's linked assets (operator-set, Phase 06) | Critical +15, High +8, Medium +0, Low −5, none set +0 |
| Exposure (simple proxy) | Whether the finding has a URL (i.e. it was observed over the network, not just inferred) | +10 / +0 |
| Exploit evidence | `Finding.verification_state` | Manually verified +15, Automated evidence +5, Unverified +0 |

```
score = clamp(severity_points[severity] × confidence_multiplier[confidence]
             + asset_criticality_bonus + exposure_bonus + verification_bonus, 0, 100)
```

The score is banded into a tier: ≥85 critical, ≥65 high, ≥40 medium, ≥15 low, else informational.

## 2. Hard rule: speculative findings cannot show as critical

A finding whose confidence is `needs_review` is capped at the **high** tier regardless of score (`app/services/risk.py::_NEEDS_REVIEW_TIER_CEILING`). With the current weights this is already true structurally — the worst case (critical severity, every bonus maxed) is 75/100, below the 85 critical threshold — but the cap is also enforced as an explicit, separate rule so the guarantee holds even if the weights above are tuned later. Verified by `tests/test_standards_and_risk.py::test_needs_review_confidence_can_never_reach_the_critical_tier`.

## 3. What this score is not

- **Not CVSS.** CVSS (when present) is a separate, library-verified field (`Finding.cvss`, see below) carried unmodified from a supplied/validated vector. The risk score never feeds into or derives from CVSS, and vice versa.
- **Not persisted.** The score is computed at read time (`app/services/findings.py::_view` / `get_finding_detail`) from the finding's current fields, never stored on the `Finding` record — so it can never drift from the data it was computed from, and changing an asset's criticality or the finding's verification state is reflected immediately.
- **Not an exploit-likelihood claim.** The "exposure" signal is a simple proxy (has a URL or not), not a verified reachability assessment — documented as a limitation directly in the API response's `notes` field.

## 4. CVSS (separate from the risk score)

`Finding.cvss` (`app/models/finding.py::CvssRecord`) stores only a `(version, vector, base_score, source, calculator)` tuple, validated by the maintained `cvss` PyPI library (3.6, LGPL-3.0-or-later — TBD-019/TBD-063): the `base_score` **must** equal what `app/models/cvss_calc.py::compute_base_score` computes from the `vector`, or the record is rejected outright. A score can therefore never be fabricated or silently mismatched from its own vector — this is enforced by a Pydantic model validator, not a UI convention, so it holds for every code path (scanners, imports, API) that ever constructs a `CvssRecord`. If no valid vector is available, `cvss` stays `null` and only the internal risk score (above) is shown, clearly labelled as internal.

## 5. Visibility and "configurability"

Per MASTER_SPEC's "the formula and weights must be visible and configurable": the weights are plain module constants in `app/services/risk.py` (visible by reading the file, or via `GET /api/risk-formula`, which every finding detail page calls to render the breakdown) and centralized in one place for a developer/owner to adjust. This release does not add a runtime Settings-UI control for them — see TBD-063 — matching the project's practice of not building speculative UI surface ahead of a stated need.
