use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use super::*;

const NOW: u64 = 1_800_000_000;
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const ISSUER: &str = "https://jckwind.proxy.ing";

fn challenge_of(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn server(answer: Answer) -> Server<MemoryStore, Always> {
    Server::new(MemoryStore::new(), Always(answer))
}

fn registered(server: &Server<MemoryStore, Always>) -> Client {
    server
        .register(
            Registration {
                client_name: Some("Claude".to_string()),
                redirect_uris: vec!["https://claude.ai/api/mcp/auth_callback".to_string()],
            },
            NOW,
        )
        .unwrap()
        .unwrap()
}

fn asked(server: &Server<MemoryStore, Always>, client: &Client) -> Ask {
    server
        .authorize(
            AuthorizeRequest {
                response_type: Some("code".to_string()),
                client_id: Some(client.id.clone()),
                redirect_uri: Some(client.redirect_uris[0].clone()),
                scope: None,
                state: Some("xyz".to_string()),
                code_challenge: Some(challenge_of(VERIFIER)),
                code_challenge_method: Some("S256".to_string()),
            },
            ISSUER,
            NOW,
        )
        .unwrap()
        .unwrap()
}

fn code_in(redirect: &str) -> String {
    redirect
        .split(['?', '&'])
        .find_map(|pair| pair.strip_prefix("code="))
        .unwrap()
        .to_string()
}

fn redeem(
    server: &Server<MemoryStore, Always>,
    client: &Client,
    code: &str,
    verifier: &str,
    at: u64,
) -> Result<Issued, TokenRefusal> {
    server
        .token(
            TokenRequest {
                grant_type: Some("authorization_code".to_string()),
                code: Some(code.to_string()),
                redirect_uri: Some(client.redirect_uris[0].clone()),
                client_id: Some(client.id.clone()),
                code_verifier: Some(verifier.to_string()),
            },
            at,
        )
        .unwrap()
}

#[test]
fn pkce_s256_matches_the_rfc_7636_example() {
    assert_eq!(
        challenge_of(VERIFIER),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
    assert!(pkce_matches(
        VERIFIER,
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    ));
    assert!(!pkce_matches(
        "not-the-verifier-but-long-enough-to-be-well-formed-ok",
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    ));
    assert!(!pkce_matches(
        "short",
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    ));
}

#[test]
fn registration_needs_a_name_and_an_allowed_redirect() {
    let server = server(Answer::Pending);
    let nameless = server
        .register(
            Registration {
                client_name: None,
                redirect_uris: vec!["https://a.example/cb".to_string()],
            },
            NOW,
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(nameless.error, "invalid_client_metadata");
    let elsewhere = server
        .register(
            Registration {
                client_name: Some("X".to_string()),
                redirect_uris: vec!["http://evil.example/cb".to_string()],
            },
            NOW,
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(elsewhere.error, "invalid_redirect_uri");
    let client = registered(&server);
    assert_eq!(client.name, "Claude");
    assert_eq!(server.store().client(&client.id).unwrap().unwrap(), client);
    let shown = Registered::from(client);
    assert_eq!(shown.token_endpoint_auth_method, "none");
    assert_eq!(shown.grant_types, ["authorization_code"]);
}

#[test]
fn an_unknown_client_or_redirect_is_a_page_and_never_a_redirect() {
    let server = server(Answer::Pending);
    let client = registered(&server);
    let unknown = server
        .authorize(
            AuthorizeRequest {
                client_id: Some("nope".to_string()),
                redirect_uri: Some("https://evil.example/".to_string()),
                ..Default::default()
            },
            ISSUER,
            NOW,
        )
        .unwrap()
        .unwrap_err();
    assert!(matches!(unknown, Refusal::Page { status: 400, .. }));
    let elsewhere = server
        .authorize(
            AuthorizeRequest {
                client_id: Some(client.id.clone()),
                redirect_uri: Some("https://evil.example/".to_string()),
                ..Default::default()
            },
            ISSUER,
            NOW,
        )
        .unwrap()
        .unwrap_err();
    assert!(matches!(elsewhere, Refusal::Page { .. }));
}

#[test]
fn a_known_client_without_pkce_is_refused_on_its_redirect_with_its_state() {
    let server = server(Answer::Pending);
    let client = registered(&server);
    let refused = server
        .authorize(
            AuthorizeRequest {
                response_type: Some("code".to_string()),
                client_id: Some(client.id.clone()),
                redirect_uri: Some(client.redirect_uris[0].clone()),
                state: Some("s 1".to_string()),
                ..Default::default()
            },
            ISSUER,
            NOW,
        )
        .unwrap()
        .unwrap_err();
    let Refusal::Redirect(url) = refused else {
        panic!("{refused:?}")
    };
    assert!(
        url.starts_with("https://claude.ai/api/mcp/auth_callback?error=invalid_request&"),
        "{url}"
    );
    assert!(
        url.contains("&state=s%201&iss=https%3A%2F%2Fjckwind.proxy.ing"),
        "{url}"
    );
    let plain = server
        .authorize(
            AuthorizeRequest {
                response_type: Some("code".to_string()),
                client_id: Some(client.id.clone()),
                redirect_uri: Some(client.redirect_uris[0].clone()),
                code_challenge: Some(challenge_of(VERIFIER)),
                code_challenge_method: Some("plain".to_string()),
                ..Default::default()
            },
            ISSUER,
            NOW,
        )
        .unwrap()
        .unwrap_err();
    assert!(matches!(plain, Refusal::Redirect(url) if url.contains("error=invalid_request")));
}

fn let_in(server: &Server<MemoryStore, Always>, client: &Client) -> (Ask, String) {
    let ask = asked(server, client);
    let Progress::Redirect(redirect) = server.progress(&ask.id, NOW).unwrap() else {
        panic!()
    };
    (ask, code_in(&redirect))
}

#[test]
fn a_code_is_bound_to_the_verifier_the_client_and_the_redirect_and_ten_minutes() {
    let server = server(Answer::Approved);
    let client = registered(&server);

    let (_, code) = let_in(&server, &client);
    let wrong_verifier = redeem(
        &server,
        &client,
        &code,
        "wrong-verifier-that-is-long-enough-to-be-well-formed-x",
        NOW + 1,
    )
    .unwrap_err();
    assert_eq!(wrong_verifier.error, "invalid_grant");
    assert_eq!(
        redeem(&server, &client, &code, VERIFIER, NOW + 2)
            .unwrap_err()
            .error,
        "invalid_grant"
    );

    let (_, code) = let_in(&server, &client);
    let other = Client {
        id: "other".to_string(),
        ..client.clone()
    };
    let wrong_client = redeem(&server, &other, &code, VERIFIER, NOW + 1).unwrap_err();
    assert_eq!(wrong_client.error, "invalid_client");
    assert_eq!(wrong_client.status(), 401);

    let (_, code) = let_in(&server, &client);
    let elsewhere = Client {
        redirect_uris: vec!["https://claude.ai/other".to_string()],
        ..client.clone()
    };
    assert_eq!(
        redeem(&server, &elsewhere, &code, VERIFIER, NOW + 1)
            .unwrap_err()
            .error,
        "invalid_grant"
    );

    let (ask, code) = let_in(&server, &client);
    let late = redeem(&server, &client, &code, VERIFIER, NOW + CODE_TTL_SECS + 1).unwrap_err();
    assert_eq!(late.error, "invalid_grant");
    assert_eq!(
        server.progress(&ask.id, NOW + CODE_TTL_SECS + 1).unwrap(),
        Progress::Gone
    );
}

#[test]
fn two_redemptions_in_flight_together_mint_one_token() {
    let server = server(Answer::Approved);
    let client = registered(&server);
    let (_, code) = let_in(&server, &client);
    let outcomes: Vec<Result<Issued, TokenRefusal>> = std::thread::scope(|scope| {
        let threads: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| redeem(&server, &client, &code, VERIFIER, NOW + 1)))
            .collect();
        threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect()
    });
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert!(
        outcomes
            .iter()
            .filter_map(|outcome| outcome.as_ref().err())
            .all(|refusal| refusal.error == "invalid_grant")
    );
    assert_eq!(server.store().live_tokens(NOW).unwrap().len(), 1);
}

#[test]
fn two_polls_that_both_see_the_yes_are_sent_to_one_code() {
    let server = server(Answer::Approved);
    let client = registered(&server);
    let ask = asked(&server, &client);
    let redirects: Vec<Progress> = std::thread::scope(|scope| {
        let threads: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| server.progress(&ask.id, NOW + 1).unwrap()))
            .collect();
        threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect()
    });
    let Progress::Redirect(first) = &redirects[0] else {
        panic!("{redirects:?}")
    };
    assert!(redirects.iter().all(|progress| progress == &redirects[0]));
    let held = server.store().ask(&ask.id).unwrap().unwrap();
    assert_eq!(held.code.as_deref(), Some(code_in(first).as_str()));
    assert!(redeem(&server, &client, &code_in(first), VERIFIER, NOW + 2).is_ok());
}

#[test]
fn nobody_answering_is_waiting_then_gone_and_no_is_access_denied() {
    let waiting = server(Answer::Pending);
    let client = registered(&waiting);
    let ask = asked(&waiting, &client);
    assert_eq!(
        waiting.progress(&ask.id, NOW + 60).unwrap(),
        Progress::Waiting
    );
    assert_eq!(
        waiting.progress(&ask.id, NOW + ASK_TTL_SECS + 1).unwrap(),
        Progress::Gone
    );
    assert_eq!(waiting.progress("nope", NOW).unwrap(), Progress::Gone);

    let denied = server(Answer::Denied);
    let client = registered(&denied);
    let ask = asked(&denied, &client);
    let Progress::Denied(url) = denied.progress(&ask.id, NOW).unwrap() else {
        panic!()
    };
    assert!(url.contains("error=access_denied"), "{url}");
    assert!(
        url.contains("&state=xyz&iss=https%3A%2F%2Fjckwind.proxy.ing"),
        "{url}"
    );
}

#[test]
fn a_revoked_token_is_not_admitted_and_is_no_longer_a_connection() {
    let server = server(Answer::Approved);
    let client = registered(&server);
    let ask = asked(&server, &client);
    let Progress::Redirect(redirect) = server.progress(&ask.id, NOW).unwrap() else {
        panic!()
    };
    let issued = redeem(&server, &client, &code_in(&redirect), VERIFIER, NOW).unwrap();
    let token = server.admit(&issued.access_token, NOW).unwrap().unwrap();

    assert_eq!(
        server
            .admit(&issued.access_token, NOW + 30)
            .unwrap()
            .unwrap()
            .last_used_at,
        Some(NOW)
    );
    assert_eq!(
        server
            .admit(&issued.access_token, NOW + 61)
            .unwrap()
            .unwrap()
            .last_used_at,
        Some(NOW + 61)
    );

    server.revoke(&issued.access_token, NOW + 100).unwrap();
    assert_eq!(server.admit(&issued.access_token, NOW + 101).unwrap(), None);
    assert!(server.store().live_tokens(NOW).unwrap().is_empty());
    assert_eq!(
        server.store().token(&token.id).unwrap().unwrap().revoked_at,
        Some(NOW + 100)
    );
    server.revoke("nothing", NOW).unwrap();
    assert!(!server.store().revoke_token("nothing", NOW).unwrap());
    assert!(server.store().revoke_token(&token.id, NOW + 200).unwrap());
    assert_eq!(
        server.store().token(&token.id).unwrap().unwrap().revoked_at,
        Some(NOW + 100)
    );
    assert_eq!(server.admit("", NOW).unwrap(), None);
}

#[test]
fn a_request_in_flight_across_a_revoke_cannot_restore_the_connection() {
    let server = server(Answer::Approved);
    let client = registered(&server);
    let ask = asked(&server, &client);
    let Progress::Redirect(redirect) = server.progress(&ask.id, NOW).unwrap() else {
        panic!()
    };
    let issued = redeem(&server, &client, &code_in(&redirect), VERIFIER, NOW).unwrap();

    let in_flight = server
        .store()
        .token_by_hash(&hash_token(&issued.access_token))
        .unwrap()
        .unwrap();
    assert!(in_flight.is_live());
    server.revoke(&issued.access_token, NOW + 10).unwrap();
    server.store().touch_token(&in_flight.id, NOW + 11).unwrap();
    let mut stale = in_flight.clone();
    stale.last_used_at = Some(NOW + 11);
    assert!(server.store().put_token(&stale).is_err());

    assert_eq!(server.admit(&issued.access_token, NOW + 12).unwrap(), None);
    assert!(server.store().live_tokens(NOW).unwrap().is_empty());
    let held = server.store().token(&in_flight.id).unwrap().unwrap();
    assert_eq!(held.revoked_at, Some(NOW + 10));
    assert_eq!(held.last_used_at, None, "a revoked token is not touched");
    server.store().touch_token("nothing", NOW).unwrap();
}

#[test]
fn a_token_opens_its_scope_for_thirty_days_and_then_the_client_asks_again() {
    let server = server(Answer::Approved);
    let client = registered(&server);
    let ask = server
        .authorize(
            AuthorizeRequest {
                response_type: Some("code".to_string()),
                client_id: Some(client.id.clone()),
                redirect_uri: Some(client.redirect_uris[0].clone()),
                scope: Some("inference threads".to_string()),
                state: None,
                code_challenge: Some(challenge_of(VERIFIER)),
                code_challenge_method: Some("S256".to_string()),
            },
            ISSUER,
            NOW,
        )
        .unwrap()
        .unwrap();
    let Progress::Redirect(redirect) = server.progress(&ask.id, NOW).unwrap() else {
        panic!()
    };
    let issued = redeem(&server, &client, &code_in(&redirect), VERIFIER, NOW).unwrap();
    assert_eq!(issued.scope, "threads inference");
    assert_eq!(issued.expires_in, Some(TOKEN_TTL_SECS));
    assert_eq!(TOKEN_TTL_SECS, 30 * 24 * 60 * 60);

    let token = server
        .admit(&issued.access_token, NOW + 1)
        .unwrap()
        .unwrap();
    assert_eq!(token.expires_at, NOW + TOKEN_TTL_SECS);
    assert_eq!(token.families(), vec!["threads", "inference"]);
    assert!(token.opens("inference"));
    assert!(!token.opens("mail"));
    assert!(
        server
            .admit(&issued.access_token, NOW + TOKEN_TTL_SECS - 1)
            .unwrap()
            .is_some()
    );
    assert_eq!(
        server
            .store()
            .live_tokens(NOW + TOKEN_TTL_SECS - 1)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        server
            .admit(&issued.access_token, NOW + TOKEN_TTL_SECS)
            .unwrap(),
        None
    );
    assert!(
        server
            .store()
            .live_tokens(NOW + TOKEN_TTL_SECS)
            .unwrap()
            .is_empty()
    );
    let held = server.store().token(&token.id).unwrap().unwrap();
    assert!(held.is_live(), "run out is not taken back");
    assert!(!held.is_live_at(NOW + TOKEN_TTL_SECS));
    assert_eq!(held.last_used_at, Some(NOW + TOKEN_TTL_SECS - 1));
}

#[test]
fn a_source_is_slowed_after_its_share_of_registrations_and_asks() {
    let server = server(Answer::Pending);
    for _ in 0..REGISTER_LIMIT.0 {
        assert!(server.may_register("203.0.113.9", NOW));
    }
    assert!(!server.may_register("203.0.113.9", NOW + 1));
    assert!(server.may_register("203.0.113.10", NOW + 1));
    assert!(server.may_register("203.0.113.9", NOW + REGISTER_LIMIT.1));
    for _ in 0..AUTHORIZE_LIMIT.0 {
        assert!(server.may_ask("203.0.113.9", NOW));
    }
    assert!(!server.may_ask("203.0.113.9", NOW + 1));
    assert!(server.may_ask("loopback", NOW + 1));

    let limiter = Limiter::new(1, 10);
    for source in 0..4096 {
        assert!(limiter.allow(&source.to_string(), NOW));
    }
    assert!(!limiter.allow("0", NOW + 5));
    assert!(limiter.allow("new", NOW + 20));
    assert_eq!(limiter.windows.lock().unwrap().len(), 1);
}
