//! One grammar for an address and the agent at it: `alex`, `alex.proxy.ing`,
//! `https://alex.proxy.ing` and `alex.proxy.ing/` all name alex's address,
//! and `alex.proxy.ing/claude` names alex's agent `claude` there.

use std::fmt;

pub const PROXY_DIRECT_AGENT_ID: &str = "proxy";

/// The domain every address lives under.
pub const DOMAIN: &str = "proxy.ing";

/// First path segments an address keeps for itself: what the router and
/// the node serve at them is never an agent, so no agent id may be one.
pub const RESERVED_SEGMENTS: &[&str] = &[
    "p",
    "c",
    "party",
    "skill",
    "a",
    "oauth",
    "client",
    "mcp",
    "inference",
    "v1",
    "devices",
    "success",
    ".well-known",
];

/// Whether a first path segment is the address's own, never an agent.
pub fn is_reserved(segment: &str) -> bool {
    RESERVED_SEGMENTS.contains(&segment)
}

/// A person's address and, when one is named, an agent of theirs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AgentAddress {
    /// The name before `.proxy.ing`.
    pub user: String,
    /// The agent after the `/`, when the text named one.
    pub agent: Option<String>,
}

/// Why a text is not an address: one short line the app shows as it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    Empty,
    NotProxyIng,
    BadName,
    NameLength,
    BadAgent,
    ReservedAgent(String),
    TooDeep,
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("an address starts with a name"),
            Self::NotProxyIng => f.write_str("an address is name or name.proxy.ing"),
            Self::BadName => f.write_str(
                "letters, numbers and hyphens only, not starting or ending with a hyphen",
            ),
            Self::NameLength => f.write_str("a name is 3 to 30 characters"),
            Self::BadAgent => f.write_str("the agent after / is letters, numbers and hyphens"),
            Self::ReservedAgent(segment) => write!(f, "/{segment} is not an agent"),
            Self::TooDeep => f.write_str("an address names one agent after the /"),
        }
    }
}

impl std::error::Error for AddressError {}

impl AgentAddress {
    pub fn parse(text: &str) -> Result<Self, AddressError> {
        let lowered = text.trim().to_ascii_lowercase();
        let mut rest = lowered.as_str();
        for scheme in ["https://", "http://"] {
            if let Some(stripped) = rest.strip_prefix(scheme) {
                rest = stripped;
                break;
            }
        }
        let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
        let user = match host.strip_suffix(DOMAIN).and_then(|h| h.strip_suffix('.')) {
            Some(user) => user,
            None if host.contains('.') => return Err(AddressError::NotProxyIng),
            None => host,
        };
        let user = normalize_user(user)?;
        let path = path.strip_suffix('/').unwrap_or(path);
        let agent = match path {
            "" => None,
            path if path.contains('/') => return Err(AddressError::TooDeep),
            path => Some(normalize_agent(path)?),
        };
        Ok(Self { user, agent })
    }

    pub fn agent_or_default(&self) -> &str {
        self.agent.as_deref().unwrap_or(PROXY_DIRECT_AGENT_ID)
    }

    pub fn host(&self) -> String {
        format!("{}.{DOMAIN}", self.user)
    }

    pub fn origin(&self) -> String {
        format!("https://{}", self.host())
    }
}

impl fmt::Display for AgentAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{DOMAIN}", self.user)?;
        if let Some(agent) = &self.agent {
            write!(f, "/{agent}")?;
        }
        Ok(())
    }
}

impl std::str::FromStr for AgentAddress {
    type Err = AddressError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

pub fn normalize_user(raw: &str) -> Result<String, AddressError> {
    let user = raw.trim().to_ascii_lowercase();
    if user.is_empty() {
        return Err(AddressError::Empty);
    }
    if !user
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(AddressError::BadName);
    }
    if user.starts_with('-') || user.ends_with('-') {
        return Err(AddressError::BadName);
    }
    if !(3..=30).contains(&user.len()) {
        return Err(AddressError::NameLength);
    }
    Ok(user)
}

pub fn normalize_agent(raw: &str) -> Result<String, AddressError> {
    let agent = raw.trim().to_ascii_lowercase();
    if !is_agent_id(&agent) {
        return Err(AddressError::BadAgent);
    }
    if is_reserved(&agent) {
        return Err(AddressError::ReservedAgent(agent));
    }
    Ok(agent)
}

pub fn is_addressable_id(id: &str) -> bool {
    is_agent_id(id) && !is_reserved(id)
}

fn is_agent_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

pub fn host_of_user(user: &str) -> Option<String> {
    normalize_user(user)
        .ok()
        .map(|user| format!("{user}.{DOMAIN}"))
}
