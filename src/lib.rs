//! # Eludrs
//!
//! A simple asynchronous wrapper for the Eludris API
//!
//! ## Installation
//!
//! Just run the following command:
//!
//! ```sh
//! cargo add --git https://github.com/eludris-community/eludrs
//! ```
//!
//! > **Note**
//! > You may be wondering why this is not on crates.io, that's because Eludris is
//! > still in early development stages, expect a release when Eludris is more stable.
//!
//! ## Example
//!
//! While an API wrapper has many uses, here's an example of what most people will
//! end up using this for, making Bots:
//!
//! ```ignore
//! # use eludrs::{HttpClient, models::Event};
//! # use futures::stream::StreamExt;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! let mut http = HttpClient::new("YOUR TOKEN HERE");
//! let gateway = http.create_gateway().await?; // uses the InstanceInfo of the instance
//! let mut events = gateway.get_events().await.unwrap();
//!
//! while let Some(event) = events.next().await {
//!     if let Event::Message(msg) = event {
//!         if msg.content == "!ping" {
//!             http.send("Pong").await.unwrap();
//!         }
//!     }
//! }
//! #  Ok(())
//! # }
//! ```
//!
//! ## Docs
//!
//! If you want documentation you can currently get that by going to your project
//! and running
//!
//! ```shell
//! cargo doc -p eludrs --open
//! ```
mod gateway;
mod http;
pub mod models;

pub use gateway::{Events, GatewayClient};
pub use http::HttpClient;

/// All the todel models re-exported
pub mod todel {
    pub use todel::models::*;
}

/// The default rest url
pub const REST_URL: &str = "https://eludris.tooty.xyz";

/// The default gateway url
pub const GATEWAY_URL: &str = "wss://eludris.tooty.xyz/ws/";
