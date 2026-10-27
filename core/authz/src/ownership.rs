//! Inferring which identity owns an object, from the traffic alone.
//!
//! The access-control sweep needs two things a human used to supply by hand: *which values
//! are object identifiers*, and *who owns each one*. The first is what [`crate::suggest`]
//! already offers. This module supplies the second, and promotes the pair into an actionable
//! object slot the sweep can target.
//!
//! The method is conservative on purpose. A value is attributed to an identity only when it
//! appears in that identity's own captured traffic and in **no other identity's** — and a
//! request is attributed to an identity only when **exactly one** identity's credential
//! matches it. Everything else is reported as ambiguous or unattributed rather than guessed,
//! because the failure this guards against is not "missed an object" — it is inferring the
//! wrong owner, which manufactures a cross-user leak that is not real, with a real person's
//! name on it. Under-attributing is recoverable; a false IDOR is not.
//!
//! This sends nothing. It reads captured traffic, the suggested candidates and the declared
//! identities, and returns a report.

use std::collections::BTreeMap;

use nullhawk_storage::repository::Limit;
use nullhawk_storage::TrafficStore;
use nullhawk_types::candidate::{CandidateStatus, IdentifierCandidate};
use nullhawk_types::identity::{Credential, Identity};
use nullhawk_types::ids::{IdentityId, RequestId};
use nullhawk_types::object::ObjectLocation;
use nullhawk_types::Result;
use serde::Serialize;

/// How many exchanges one inference reads. Matches the suggestion analyzer's window.
const MAX_EXCHANGES: u32 = 2_000;

/// The shortest value worth matching as an object id. Below this a substring search finds
/// coincidences, not identifiers — the same floor the leak detector uses.
const MIN_OBJECT_ID_LEN: usize = 4;

/// An object identifier whose owner the traffic revealed.
#[derive(Debug, Clone, Serialize)]
pub struct OwnedObject {
    /// The identifier, exactly as it appeared in traffic. Never decoded.
    pub value: String,
    /// A readable description of where it sat, e.g. `JSON field accountId`.
    pub descriptor: String,
    /// Where to address it in a request, for the sweep to substitute.
    pub location: ObjectLocation,
    /// The identity it was attributed to (display label).
    pub owner: String,
    /// That identity's id — what the sweep builds a declaration against.
    pub owner_id: IdentityId,
    /// A captured request of the owner's that carried this value, for the sweep to build
    /// the cross-identity attempt from.
    pub base: RequestId,
    /// How many of the owner's requests carried this value.
    pub occurrences: usize,
}

/// What an inference produced.
#[derive(Debug, Clone, Default, Serialize)]
pub struct OwnershipReport {
    /// Candidates attributed to exactly one identity — ready for the sweep.
    pub objects: Vec<OwnedObject>,
    /// How many suggested candidates were considered.
    pub considered: usize,
    /// Values that appeared in more than one identity's traffic — shared or public, not a
    /// single owner's object, so not something a cross-user test should target.
    pub ambiguous: usize,
    /// Values that were seen, but in no request any identity's credential matched — owner
    /// unknown. Usually means the traffic was captured before the identities were declared,
    /// or without a logged-in session.
    pub unattributed: usize,
    /// How many identities were available to attribute against.
    pub identities: usize,
}

/// Read the project's traffic and infer, for each suggested candidate, which identity owns it.
///
/// Sends nothing. `candidates` are the values [`crate::suggest`] offered; `identities` are the
/// ones declared on the project.
pub fn infer(
    traffic: &TrafficStore,
    candidates: &[IdentifierCandidate],
    identities: &[Identity],
) -> Result<OwnershipReport> {
    let page = traffic.history(None, Limit::new(MAX_EXCHANGES))?;
    let mut requests = Vec::with_capacity(page.items.len());
    for item in &page.items {
        let request = traffic.request(item.id)?;
        let headers = CallerHeaders::from_raw(&request.headers_raw);
        // Where an object id lives in a request: the target and the body. Headers are left
        // out — the session cookie is in there, and a value that only ever appears beside a
        // credential is not evidence of ownership.
        let haystack = format!(
            "{} {}",
            request.path,
            String::from_utf8_lossy(&request.body)
        );
        requests.push((item.id, headers, haystack));
    }
    Ok(tally(&requests, candidates, identities))
}

/// The pure core: given each request's identifying headers and searchable text, attribute
/// every candidate to an owner where the traffic allows exactly one.
fn tally(
    requests: &[(RequestId, CallerHeaders, String)],
    candidates: &[IdentifierCandidate],
    identities: &[Identity],
) -> OwnershipReport {
    let mut report = OwnershipReport {
        identities: identities.len(),
        ..Default::default()
    };

    for candidate in candidates {
        // A value a human already judged is not an object, or that a newer analysis replaced,
        // is not reconsidered here.
        if matches!(
            candidate.status,
            CandidateStatus::Rejected | CandidateStatus::Superseded
        ) {
            continue;
        }
        if candidate.value.len() < MIN_OBJECT_ID_LEN {
            continue;
        }
        report.considered += 1;

        // Count, per identity, how many of *their* requests carried this value, and keep the
        // first such request as the base the sweep will build its cross-identity attempt from.
        // Keyed by the id's string so no ordering trait is required of the id type.
        let mut per_owner: BTreeMap<String, (IdentityId, String, usize, RequestId)> =
            BTreeMap::new();
        for (request, headers, haystack) in requests {
            if !haystack.contains(&candidate.value) {
                continue;
            }
            if let Some(identity) = caller(headers, identities) {
                let entry = per_owner
                    .entry(identity.id.to_string())
                    .or_insert_with(|| (identity.id, identity.label.clone(), 0, *request));
                entry.2 += 1;
            }
        }

        match per_owner.len() {
            // Exactly one identity used it, and no other did: a clean owner.
            1 => {
                let (_, (owner_id, owner, occurrences, base)) =
                    per_owner.into_iter().next().expect("one entry");
                report.objects.push(OwnedObject {
                    value: candidate.value.clone(),
                    descriptor: candidate.descriptor.clone(),
                    location: candidate.location.clone(),
                    owner,
                    owner_id,
                    base,
                    occurrences,
                });
            }
            // Used by several identities — shared or public, not one owner's object.
            n if n > 1 => report.ambiguous += 1,
            // Seen, but nobody's credential matched the requests that carried it.
            _ => report.unattributed += 1,
        }
    }

    // Deterministic order: strongest (most sightings) first, then by value.
    report
        .objects
        .sort_by(|a, b| (b.occurrences, &b.value).cmp(&(a.occurrences, &a.value)));
    report
}

/// Which declared identity a captured request was sent as — `Some` only when **exactly one**
/// identity's credential matches. `None` on no match or more than one: a wrong attribution
/// fabricates a leak, so the tie goes to silence.
fn caller<'a>(headers: &CallerHeaders, identities: &'a [Identity]) -> Option<&'a Identity> {
    let mut found: Option<&Identity> = None;
    for identity in identities {
        if belongs_to(headers, identity) {
            if found.is_some() {
                return None;
            }
            found = Some(identity);
        }
    }
    found
}

/// Whether a request's identifying headers match an identity's credential. Mirrors the
/// scheduler's `Subject::whose`, kept here because `core/active` depends on `core/authz` and
/// not the other way around.
fn belongs_to(headers: &CallerHeaders, identity: &Identity) -> bool {
    // A cookie jar is a dozen values; only the named session cookies say who is calling, so
    // compare exactly those. Comparing the whole jar never matches (analytics/consent cookies
    // differ per request), and matching loosely would attribute a request to the wrong person.
    if !identity.session_cookies.is_empty() {
        if let Credential::Cookie { value } = &identity.credential {
            return match headers.get("cookie") {
                Some(sent) => session_matches(sent, value.expose(), &identity.session_cookies),
                None => false,
            };
        }
        return false;
    }

    match &identity.credential {
        Credential::Bearer { token } => match headers.get("authorization") {
            Some(auth) => {
                let sent = strip_bearer(auth);
                // A rotating JWT never matches byte for byte, so compare the subject claim —
                // the application's own signed statement of whose request this is. An opaque
                // token asserts nothing, so for it the comparison is the token itself.
                match nullhawk_types::expiry::subject_of(token.expose()) {
                    Some(declared) => {
                        nullhawk_types::expiry::subject_of(sent).as_deref() == Some(&declared)
                    }
                    None => sent == token.expose(),
                }
            }
            None => false,
        },
        Credential::Cookie { value } => headers.get("cookie") == Some(value.expose().as_str()),
        Credential::Header { name, value } => headers.get(name) == Some(value.expose().as_str()),
        // Basic-auth and credential-less identities are not attributed from traffic here —
        // rare for the multi-identity web/API case, and not worth a guess.
        Credential::Basic { .. } | Credential::None => false,
    }
}

/// The identifying headers of a captured request, parsed once from the raw block.
struct CallerHeaders {
    /// `(lowercase name, value)` pairs.
    pairs: Vec<(String, String)>,
}

impl CallerHeaders {
    fn from_raw(raw: &[u8]) -> Self {
        let pairs = String::from_utf8_lossy(raw)
            .lines()
            .filter_map(|line| {
                line.split_once(':')
                    .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_string()))
            })
            .collect();
        Self { pairs }
    }

    fn get(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.pairs
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Strip a `Bearer ` prefix (either casing) from an `Authorization` value.
fn strip_bearer(value: &str) -> &str {
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .unwrap_or(value)
        .trim()
}

/// Whether a request's cookie header carries the same session as a declared one: every named
/// cookie present in both and equal. All of them, not any — half a match is not a match.
fn session_matches(sent: &str, declared: &str, names: &[String]) -> bool {
    names.iter().all(
        |name| match (cookie_in(sent, name), cookie_in(declared, name)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        },
    )
}

/// One cookie's value out of a `Cookie` header.
fn cookie_in<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key.trim() == name).then(|| value.trim())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nullhawk_types::candidate::IdentifierCandidate;
    use nullhawk_types::identity::{Credential, Identity};
    use nullhawk_types::ids::CandidateId;
    use nullhawk_types::object::ObjectLocation;
    use nullhawk_types::redact::Secret;

    fn cookie_identity(label: &str, cookie: &str, names: &[&str]) -> Identity {
        Identity {
            label: label.into(),
            credential: Credential::Cookie {
                value: Secret::new(cookie.into()),
            },
            session_cookies: names.iter().map(|s| s.to_string()).collect(),
            ..Identity::anonymous()
        }
    }

    fn headers(lines: &str) -> CallerHeaders {
        CallerHeaders::from_raw(lines.replace('\n', "\r\n").as_bytes())
    }

    /// One captured request's inputs to `tally`: a fresh id, its caller headers, and the
    /// searchable text (path + body) object ids are matched against.
    fn sighting(headers: CallerHeaders, text: &str) -> (RequestId, CallerHeaders, String) {
        (RequestId::new(), headers, text.to_string())
    }

    fn candidate(value: &str) -> IdentifierCandidate {
        IdentifierCandidate {
            id: CandidateId::new(),
            value: value.into(),
            location: ObjectLocation::Anywhere,
            descriptor: format!("value {value}"),
            source_request: None,
            occurrences: 1,
            live_observations: 1,
            signals: Vec::new(),
            score: 10,
            status: CandidateStatus::Proposed,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn a_named_session_cookie_attributes_to_its_owner() {
        let a = cookie_identity("A", "session=aaa; theme=dark", &["session"]);
        let b = cookie_identity("B", "session=bbb; theme=dark", &["session"]);
        let ids = [a, b];

        // The session cookie is what decides it, even though `theme` is shared.
        let req = headers("Host: app\nCookie: theme=dark; session=aaa");
        assert_eq!(caller(&req, &ids).map(|i| i.label.as_str()), Some("A"));

        // A request with the other session is the other identity.
        let req_b = headers("Cookie: session=bbb; theme=dark");
        assert_eq!(caller(&req_b, &ids).map(|i| i.label.as_str()), Some("B"));

        // A session value that matches nobody is attributed to nobody — never guessed.
        let req_x = headers("Cookie: session=zzz");
        assert!(caller(&req_x, &ids).is_none());
    }

    #[test]
    fn a_bearer_jwt_attributes_by_its_subject_not_its_bytes() {
        // Two tokens for the same subject but different expiries: same person.
        // {"sub":"user-a"} with two different trailing segments.
        let t1 = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLWEifQ.sig1";
        let t2 = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLWEifQ.sig2";
        let a = Identity::bearer("A", t1);
        let ids = [a];
        // A later request carries a freshly-issued token for the same subject.
        let req = headers(&format!("Authorization: Bearer {t2}"));
        assert_eq!(caller(&req, &ids).map(|i| i.label.as_str()), Some("A"));
    }

    #[test]
    fn two_identities_matching_the_same_request_is_no_attribution() {
        // Pathological, but the rule must hold: a tie goes to silence, not a coin-flip.
        let a = Identity::bearer("A", "opaque-token");
        let b = Identity::bearer("B", "opaque-token");
        let ids = [a, b];
        let req = headers("Authorization: Bearer opaque-token");
        assert!(caller(&req, &ids).is_none());
    }

    #[test]
    fn an_object_used_only_by_one_identity_gets_that_owner() {
        let a = cookie_identity("A", "session=aaa", &["session"]);
        let b = cookie_identity("B", "session=bbb", &["session"]);
        let ids = [a, b];
        let reqs = vec![
            sighting(headers("Cookie: session=aaa"), "/account/INV-1001"),
            sighting(headers("Cookie: session=aaa"), "/account/INV-1001/pdf"),
            sighting(headers("Cookie: session=bbb"), "/account/INV-2002"),
        ];
        let report = tally(&reqs, &[candidate("INV-1001"), candidate("INV-2002")], &ids);
        assert_eq!(report.objects.len(), 2);
        assert_eq!(report.ambiguous, 0);
        assert_eq!(report.unattributed, 0);
        let inv1001 = report
            .objects
            .iter()
            .find(|o| o.value == "INV-1001")
            .unwrap();
        assert_eq!(inv1001.owner, "A");
        assert_eq!(inv1001.occurrences, 2);
    }

    #[test]
    fn a_value_two_identities_use_is_ambiguous_not_owned() {
        let a = cookie_identity("A", "session=aaa", &["session"]);
        let b = cookie_identity("B", "session=bbb", &["session"]);
        let ids = [a, b];
        let reqs = vec![
            sighting(headers("Cookie: session=aaa"), "/catalog/WIDGET"),
            sighting(headers("Cookie: session=bbb"), "/catalog/WIDGET"),
        ];
        let report = tally(&reqs, &[candidate("WIDGET")], &ids);
        assert!(report.objects.is_empty());
        assert_eq!(report.ambiguous, 1);
    }

    #[test]
    fn a_value_in_unattributable_traffic_is_counted_not_owned() {
        let a = cookie_identity("A", "session=aaa", &["session"]);
        let ids = [a];
        // The request carries nobody's known session.
        let reqs = vec![sighting(headers("Cookie: session=unknown"), "/x/TOKEN123")];
        let report = tally(&reqs, &[candidate("TOKEN123")], &ids);
        assert!(report.objects.is_empty());
        assert_eq!(report.unattributed, 1);
    }

    #[test]
    fn rejected_and_too_short_candidates_are_skipped() {
        let a = cookie_identity("A", "session=aaa", &["session"]);
        let ids = [a];
        let reqs = vec![sighting(
            headers("Cookie: session=aaa"),
            "/a/AB /b/LONGVALUE",
        )];
        let mut rejected = candidate("LONGVALUE");
        rejected.status = CandidateStatus::Rejected;
        let report = tally(&reqs, &[rejected, candidate("AB")], &ids);
        // The rejected one and the two-character one are both skipped.
        assert_eq!(report.considered, 0);
        assert!(report.objects.is_empty());
    }
}
