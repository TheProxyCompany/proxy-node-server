//! OAuth [`Store`] and [`Consent`] traits plus the in-memory reference
//! implementations ([`MemoryStore`], [`Always`]).

use std::collections::HashMap;
use std::sync::Mutex;

use super::{Answer, Ask, Client, OAuthError, Token};

/// Storage seam for OAuth clients, asks, and tokens.
pub trait Store: Send + Sync {
    fn put_client(&self, client: &Client) -> Result<(), OAuthError>;
    fn client(&self, id: &str) -> Result<Option<Client>, OAuthError>;
    fn put_ask(&self, ask: &Ask) -> Result<(), OAuthError>;
    fn ask(&self, id: &str) -> Result<Option<Ask>, OAuthError>;
    fn mint_code(&self, id: &str, code: &str, now: u64) -> Result<Option<Ask>, OAuthError>;
    fn redeem_code(&self, code: &str) -> Result<Option<Ask>, OAuthError>;
    fn put_token(&self, token: &Token) -> Result<(), OAuthError>;
    fn revoke_token(&self, id: &str, now: u64) -> Result<bool, OAuthError>;
    fn touch_token(&self, id: &str, used_at: u64) -> Result<(), OAuthError>;
    fn token(&self, id: &str) -> Result<Option<Token>, OAuthError>;
    fn token_by_hash(&self, hash: &str) -> Result<Option<Token>, OAuthError>;
    fn live_tokens(&self, now: u64) -> Result<Vec<Token>, OAuthError>;
}

/// Consent seam for presenting an authorization [`Ask`] to the user and polling
/// their [`Answer`].
pub trait Consent: Send + Sync {
    fn ask(&self, ask: &Ask) -> Result<(), OAuthError>;
    fn answer(&self, ask: &Ask) -> Result<Answer, OAuthError>;
}

/// Reference in-memory [`Store`].
#[derive(Default)]
pub struct MemoryStore {
    clients: Mutex<HashMap<String, Client>>,
    asks: Mutex<HashMap<String, Ask>>,
    tokens: Mutex<HashMap<String, Token>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

fn poisoned<T>(_: std::sync::PoisonError<T>) -> OAuthError {
    OAuthError::Store("memory store lock poisoned".to_string())
}

impl Store for MemoryStore {
    fn put_client(&self, client: &Client) -> Result<(), OAuthError> {
        self.clients
            .lock()
            .map_err(poisoned)?
            .insert(client.id.clone(), client.clone());
        Ok(())
    }

    fn client(&self, id: &str) -> Result<Option<Client>, OAuthError> {
        Ok(self.clients.lock().map_err(poisoned)?.get(id).cloned())
    }

    fn put_ask(&self, ask: &Ask) -> Result<(), OAuthError> {
        self.asks
            .lock()
            .map_err(poisoned)?
            .insert(ask.id.clone(), ask.clone());
        Ok(())
    }

    fn ask(&self, id: &str) -> Result<Option<Ask>, OAuthError> {
        Ok(self.asks.lock().map_err(poisoned)?.get(id).cloned())
    }

    fn mint_code(&self, id: &str, code: &str, now: u64) -> Result<Option<Ask>, OAuthError> {
        let mut asks = self.asks.lock().map_err(poisoned)?;
        let Some(ask) = asks.get_mut(id) else {
            return Ok(None);
        };
        if ask.code.is_none() {
            ask.code = Some(code.to_string());
            ask.code_issued_at = Some(now);
        }
        Ok(Some(ask.clone()))
    }

    fn redeem_code(&self, code: &str) -> Result<Option<Ask>, OAuthError> {
        let mut asks = self.asks.lock().map_err(poisoned)?;
        let Some(ask) = asks
            .values_mut()
            .find(|ask| !ask.code_used && ask.code.as_deref() == Some(code))
        else {
            return Ok(None);
        };
        ask.code_used = true;
        Ok(Some(ask.clone()))
    }

    fn put_token(&self, token: &Token) -> Result<(), OAuthError> {
        let mut tokens = self.tokens.lock().map_err(poisoned)?;
        if tokens.contains_key(&token.id) {
            return Err(OAuthError::Store(format!(
                "token {} is already held",
                token.id
            )));
        }
        tokens.insert(token.id.clone(), token.clone());
        Ok(())
    }

    fn revoke_token(&self, id: &str, now: u64) -> Result<bool, OAuthError> {
        let mut tokens = self.tokens.lock().map_err(poisoned)?;
        let Some(held) = tokens.get_mut(id) else {
            return Ok(false);
        };
        if held.revoked_at.is_none() {
            held.revoked_at = Some(now);
        }
        Ok(true)
    }

    fn touch_token(&self, id: &str, used_at: u64) -> Result<(), OAuthError> {
        if let Some(held) = self.tokens.lock().map_err(poisoned)?.get_mut(id) {
            if held.is_live() {
                held.last_used_at = Some(used_at);
            }
        }
        Ok(())
    }

    fn token(&self, id: &str) -> Result<Option<Token>, OAuthError> {
        Ok(self.tokens.lock().map_err(poisoned)?.get(id).cloned())
    }

    fn token_by_hash(&self, hash: &str) -> Result<Option<Token>, OAuthError> {
        Ok(self
            .tokens
            .lock()
            .map_err(poisoned)?
            .values()
            .find(|token| token.hash == hash)
            .cloned())
    }

    fn live_tokens(&self, now: u64) -> Result<Vec<Token>, OAuthError> {
        let mut tokens: Vec<Token> = self
            .tokens
            .lock()
            .map_err(poisoned)?
            .values()
            .filter(|token| token.is_live_at(now))
            .cloned()
            .collect();
        tokens.sort_by(|a, b| a.issued_at.cmp(&b.issued_at).then(a.id.cmp(&b.id)));
        Ok(tokens)
    }
}

/// Test double: a [`Consent`] that answers every ask with a fixed [`Answer`].
#[derive(Clone, Copy, Debug)]
pub struct Always(pub Answer);

impl Consent for Always {
    fn ask(&self, _ask: &Ask) -> Result<(), OAuthError> {
        Ok(())
    }

    fn answer(&self, _ask: &Ask) -> Result<Answer, OAuthError> {
        Ok(self.0)
    }
}
