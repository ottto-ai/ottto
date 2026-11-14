//! The daily-reference read identity equals the Codex session creator pair
//! for the same ids, so a provider read and Ottto's sessions join on one key.

use crate::provider_daily_reference::logins::{codex_read_identity, ReadIdentity};
use crate::snapshots::codex_raw_creator_pair;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Serialize;
use serde_json::{json, Value};

#[derive(Serialize)]
struct IdentityVector {
    case: &'static str,
    user_id: &'static str,
    workspace_id: &'static str,
    account_identifier_hash: String,
    provider_workspace_hash: String,
}

#[derive(Serialize)]
struct IdentityVectors {
    schema_version: u16,
    hash_scheme: &'static str,
    vectors: Vec<IdentityVector>,
}

fn access_token(user: &str, workspace: &str) -> String {
    let encode = |value: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("json"));
    let claims = json!({
        "iss": "https://auth.openai.com",
        "aud": "app_fixture",
        "exp": 4_102_444_800_i64,
        "https://api.openai.com/auth": {
            "chatgpt_user_id": user,
            "chatgpt_account_id": workspace,
        },
    });
    format!(
        "{}.{}.signature",
        encode(&json!({"alg": "RS256"})),
        encode(&claims)
    )
}

/// [money] Same ids through the read path (access-token claims) and the
/// session path (rollout `session_meta`) give the same hash pair, and the
/// emitted cross-language vectors are the committed file.
#[test]
fn read_identity_matches_the_session_creator_pair_and_the_vectors_file() {
    let cases = [
        (
            "same_user_workspace_a",
            "user-synthetic-0001",
            "ws-synthetic-a",
        ),
        (
            "same_user_workspace_b",
            "user-synthetic-0001",
            "ws-synthetic-b",
        ),
        (
            "two_users_shared_workspace_first",
            "user-synthetic-0002",
            "ws-synthetic-shared",
        ),
        (
            "two_users_shared_workspace_second",
            "user-synthetic-0003",
            "ws-synthetic-shared",
        ),
        (
            "ascii_case_and_surrounding_whitespace",
            "  User-Synthetic-0001 ",
            "\tWS-Synthetic-A ",
        ),
    ];
    let mut vectors = Vec::new();
    for (case, user_id, workspace_id) in cases {
        let ReadIdentity::Usable {
            identity: Some(identity),
            ..
        } = codex_read_identity(
            &access_token(user_id, workspace_id),
            None,
            Some(workspace_id.trim()),
        )
        else {
            panic!("{case}: the read path did not identify the login");
        };
        let wire = serde_json::to_value(&identity).expect("identity");
        assert_eq!(wire["identity_hash_scheme"], json!("provider-sha256:v1"));
        let session = codex_raw_creator_pair(&json!({
            "creator_user_id": user_id,
            "creator_account_id": workspace_id,
        }))
        .expect("creator pair");
        assert_eq!(
            (
                wire["account_identifier_hash"].as_str(),
                wire["provider_workspace_hash"].as_str()
            ),
            (Some(session.0.as_str()), Some(session.1.as_str())),
            "{case}"
        );
        vectors.push(IdentityVector {
            case,
            user_id,
            workspace_id,
            account_identifier_hash: session.0,
            provider_workspace_hash: session.1,
        });
    }
    let file = serde_json::to_value(IdentityVectors {
        schema_version: 1,
        hash_scheme: "provider-sha256:v1",
        vectors,
    })
    .expect("vectors");
    assert_eq!(
        format!("{}\n", serde_json::to_string_pretty(&file).expect("pretty")),
        include_str!(
            "../../../../../../../fixtures/provider-daily-reference/provider-daily-reference-identity-vectors.v1.json"
        )
    );
}
