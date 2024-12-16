use serde::{Deserialize, Serialize};
use todel::models::{
    Category, CategoryEdit, ErrorResponse, Message, Sphere, SphereChannel, SphereChannelEdit,
    Status, User,
};

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
    /// A users data has been updated
    UserUpdate(User),
    /// A user's status has been updated
    PresenceUpdate { user_id: u64, status: Status },
    /// This user has joined a sphere
    SphereJoin(Sphere),
    /// A user has joined a sphere
    SphereMemberJoin { user: User, sphere_id: u64 },
    /// A category has been created
    CategoryCreate { category: Category, sphere_id: u64 },
    /// A category has been edited
    CategoryEdit {
        data: CategoryEdit,
        category_id: u64,
        sphere_id: u64,
    },
    /// A category has been deleted
    CategoryDelete { category_id: u64, sphere_id: u64 },
    /// A channel has been created
    SphereChannelCreate {
        channel: SphereChannel,
        sphere_id: u64,
    },
    /// A channel has been edited
    SphereChannelEdit {
        data: SphereChannelEdit,
        channel_id: u64,
        sphere_id: u64,
    },
    /// A channel has been deleted
    SphereChannelDelete { channel_id: u64, sphere_id: u64 },
}
