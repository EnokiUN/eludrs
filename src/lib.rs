//! A simple rust library for interacting with the Eludris API
mod gateway;
mod http;
mod models;

pub use gateway::{Events, GatewayClient, GATEWAY_URL};
pub use http::{HttpClient, REST_URL};

/// All the todel models re-exported
pub mod todel {
    pub use todel::models::*;
}
