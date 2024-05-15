use serde::{Deserialize, Serialize};
use todel::{ErrorResponse, Message, Status, User};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum HttpResponse<T> {
    Success(T),
    Error(ErrorResponse),
}

/// An abstraction over gateway event types
#[derive(Debug, Clone)]
pub enum Event {
    /// An indication that the client has succesfully authenticated
    Authenticated,
    /// A message that has just been sent over the gateway
    Message(Message),
    /// The old and new data after a user has been updated
    UserUpdate { old_user: Option<User>, user: User },
    /// The old and new data after a user's status has been updated
    PresenceUpdate {
        old_status: Option<Status>,
        user_id: u64,
        status: Status,
    },
}
