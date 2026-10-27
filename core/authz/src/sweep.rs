//! The whole-app access-control sweep — turning inferred owners into a plan.
//!
//! P1 ([`crate::ownership`]) says which identity owns each object. This takes those owned
//! objects and works out the cross-identity attempts to make: for every object-bearing
//! endpoint, one construction run — the senders are every identity, and [`crate::construct`]
//! has each non-owner try to reach each object it does not own, built from the owner's own
//! captured request. The whole-sweep request ceiling is spread across the runs so no single
//! endpoint can drain it.
//!
//! This module **plans** — it works out and counts what would be sent, the way the scanner's
//! dry-run does, and sends nothing. Executing the runs (through the existing `construct`,
//! which does the sending and the judging) and ranking the leaks is the sweep's next layer.

use std::collections::BTreeMap;

use nullhawk_types::identity::Identity;
use nullhawk_types::object::ObjectDeclaration;
use nullhawk_types::programme::Programme;
use serde::Serialize;

use crate::construct::ConstructionPlan;
use crate::ownership::OwnedObject;

/// A sweep, worked out but not yet sent.
pub struct SweepPlan {
    /// One construction run per object-bearing base request.
    pub runs: Vec<ConstructionPlan>,
    /// What this plan covers, for the report and the pre-send summary.
    pub coverage: SweepCoverage,
}

/// The shape of a planned sweep — what it will and will not reach.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SweepCoverage {
    /// Inferred owned objects fed in.
    pub objects: usize,
    /// Objects that produced a valid declaration (a value safe to splice into a request).
    pub testable_objects: usize,
    /// Objects whose value could not be a declaration (e.g. it carried CR/LF) — skipped.
    pub skipped_invalid: usize,
    /// Distinct object-bearing endpoints (base requests), one construction run each.
    pub endpoints: usize,
    /// Identities available to attempt as.
    pub identities: usize,
    /// The total request ceiling across all runs.
    pub attempts_budgeted: usize,
}

/// Work out the sweep: group owned objects by the base request they were seen in, and build one
/// construction run per base. Sends nothing.
///
/// `budget` is the whole-sweep request ceiling, spread across the runs so no single endpoint can
/// consume it all. `programme` gates which identifiers may be targeted at all — the one place
/// the sweep chooses an object and puts it in somebody's request.
pub fn plan(
    objects: &[OwnedObject],
    identities: &[Identity],
    budget: usize,
    programme: &Programme,
    verify: bool,
) -> SweepPlan {
    let mut coverage = SweepCoverage {
        objects: objects.len(),
        identities: identities.len(),
        ..Default::default()
    };

    // Group objects by their base request. Keyed by the id's string so no ordering trait is
    // required of the id type; the declarations under each base keep input order.
    let mut by_base: BTreeMap<String, (nullhawk_types::ids::RequestId, Vec<ObjectDeclaration>)> =
        BTreeMap::new();
    for object in objects {
        match ObjectDeclaration::new(
            "object",
            object.value.clone(),
            object.owner_id,
            object.location.clone(),
        ) {
            Ok(declaration) => {
                coverage.testable_objects += 1;
                by_base
                    .entry(object.base.to_string())
                    .or_insert_with(|| (object.base, Vec::new()))
                    .1
                    .push(declaration.found_in(object.base));
            }
            // A value that cannot be safely spliced into a request is not swept — Nullhawk
            // never puts raw CR/LF into a request line, even its own constructed one.
            Err(_) => coverage.skipped_invalid += 1,
        }
    }

    coverage.endpoints = by_base.len();
    // Spread the ceiling across the runs so one endpoint cannot drain it; at least one each.
    let per_run = if by_base.is_empty() {
        0
    } else {
        (budget / by_base.len()).max(1)
    };

    let mut runs = Vec::with_capacity(by_base.len());
    for (_, (base, declarations)) in by_base {
        let run = ConstructionPlan::new(base, identities.to_vec(), declarations)
            .under(programme.clone())
            .with_limit(per_run)
            .verifying(verify);
        coverage.attempts_budgeted += run.limit;
        runs.push(run);
    }

    SweepPlan { runs, coverage }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nullhawk_types::ids::RequestId;
    use nullhawk_types::object::ObjectLocation;

    fn owned(value: &str, owner: &Identity, base: RequestId) -> OwnedObject {
        OwnedObject {
            value: value.into(),
            descriptor: format!("value {value}"),
            location: ObjectLocation::Anywhere,
            owner: owner.label.clone(),
            owner_id: owner.id,
            base,
            occurrences: 1,
        }
    }

    #[test]
    fn one_run_per_distinct_base_each_with_its_objects() {
        let a = Identity::bearer("A", "ta");
        let b = Identity::bearer("B", "tb");
        let ids = [a.clone(), b.clone()];
        let base1 = RequestId::new();
        let base2 = RequestId::new();
        // Two objects share base1; a third is on base2.
        let objects = vec![
            owned("INV-1001", &a, base1),
            owned("INV-1002", &a, base1),
            owned("ACC-55", &b, base2),
        ];
        let sweep = plan(&objects, &ids, 60, &Programme::none(), false);
        assert_eq!(sweep.coverage.endpoints, 2);
        assert_eq!(sweep.coverage.testable_objects, 3);
        assert_eq!(sweep.runs.len(), 2);
        // Every run offers every identity as a sender; construct decides who owns what.
        assert!(sweep.runs.iter().all(|r| r.senders.len() == 2));
        // The run on base1 carries both of its objects.
        let total_decls: usize = sweep.runs.iter().map(|r| r.declarations.len()).sum();
        assert_eq!(total_decls, 3);
    }

    #[test]
    fn the_budget_is_spread_across_runs_not_given_to_each() {
        let a = Identity::bearer("A", "ta");
        let ids = [a.clone()];
        let objects = vec![
            owned("X-0001", &a, RequestId::new()),
            owned("X-0002", &a, RequestId::new()),
        ];
        // Budget 10 over 2 endpoints → 5 each, 10 total — not 10 each.
        let sweep = plan(&objects, &ids, 10, &Programme::none(), false);
        assert_eq!(sweep.runs.len(), 2);
        assert!(sweep.runs.iter().all(|r| r.limit == 5));
        assert_eq!(sweep.coverage.attempts_budgeted, 10);
    }

    #[test]
    fn a_value_that_cannot_be_spliced_is_skipped_not_swept() {
        let a = Identity::bearer("A", "ta");
        let ids = [a.clone()];
        // A CR/LF in the value would be request splitting; the declaration constructor rejects
        // it, so it is counted as skipped and never reaches a run.
        let objects = vec![
            owned("GOOD-1", &a, RequestId::new()),
            owned("bad\r\nvalue", &a, RequestId::new()),
        ];
        let sweep = plan(&objects, &ids, 20, &Programme::none(), false);
        assert_eq!(sweep.coverage.testable_objects, 1);
        assert_eq!(sweep.coverage.skipped_invalid, 1);
        assert_eq!(sweep.coverage.endpoints, 1);
    }

    #[test]
    fn no_objects_is_an_empty_plan_not_a_panic() {
        let sweep = plan(&[], &[], 50, &Programme::none(), false);
        assert!(sweep.runs.is_empty());
        assert_eq!(sweep.coverage.endpoints, 0);
        assert_eq!(sweep.coverage.attempts_budgeted, 0);
    }
}
