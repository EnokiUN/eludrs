use crate::{models::HttpResponse, GatewayClient, REST_URL};
use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{fmt::Display, time::Duration};
use todel::{ErrorResponse, InstanceInfo, Message, MessageCreate};
use tokio::time;

/// Simple Http client
#[derive(Debug, Clone)]
pub struct HttpClient {
    client: Client,
    instance_info: Option<InstanceInfo>,
    token: String,
    pub rest_url: String,
}

impl HttpClient {
    /// Create a new HttpClient
    pub fn new(token: &str) -> Self {
        HttpClient {
            client: Client::new(),
            instance_info: None,
            token: token.to_string(),
            rest_url: REST_URL.to_string(),
        }
    }

    /// Change the url of the HttpClient
    ///
    /// # Example:
    /// ```rust
    /// use eludrs::HttpClient;
    ///
    /// let client = HttpClient::new().rest_url("http://0.0.0.0:7159".to_string());
    ///
    /// assert_eq!(client.rest_url, "http://0.0.0.0:7159".to_string())
    /// ```
    pub fn rest_url(mut self, url: String) -> Self {
        self.rest_url = url;
        self
    }

    /// Fetch the info payload of an instance
    pub async fn fetch_instance_info(&self) -> Result<InstanceInfo> {
        Ok(self.client.get(&self.rest_url).send().await?.json().await?)
    }

    /// Try to get the client's internal InstanceInfo or fetch it if it does not already exist
    pub async fn get_instance_info(&mut self) -> Result<&InstanceInfo> {
        if self.instance_info.is_some() {
            Ok(self.instance_info.as_ref().unwrap())
        } else {
            self.instance_info = Some(self.fetch_instance_info().await?);
            Ok(self.instance_info.as_ref().unwrap())
        }
    }

    async fn request<T: for<'a> Deserialize<'a>, B: Serialize + Sized>(
        &self,
        path: &str,
        body: Option<B>,
    ) -> Result<HttpResponse<T>> {
        loop {
            match self
                .client
                .post(format!("{}/{}", self.rest_url, path))
                .header("Authorization", &self.token)
                .json(&body)
                .send()
                .await?
                .json::<HttpResponse<T>>()
                .await
            {
                Ok(HttpResponse::Success(data)) => {
                    break Ok(HttpResponse::Success(data));
                }
                Ok(HttpResponse::Error(err)) => match err {
                    ErrorResponse::RateLimited { retry_after, .. } => {
                        log::info!(
                            "Client got ratelimited at /{}, retrying in {}ms",
                            path,
                            retry_after
                        );
                        time::sleep(Duration::from_millis(retry_after)).await;
                    }
                    ErrorResponse::Validation {
                        value_name, info, ..
                    } => {
                        Err(anyhow::anyhow!(
                            "Ran into a validation error with field {}: {}",
                            value_name,
                            info,
                        ))?;
                    }
                    err => Err(anyhow::anyhow!("Could not send message: {:?}", err))?,
                },
                Err(err) => {
                    break Err(err)?;
                }
            }
        }
    }

    /// Send a message
    pub async fn send_message<C: Display>(&self, content: C) -> Result<Message> {
        let message = MessageCreate {
            content: content.to_string(),
            disguise: None,
        };
        match self
            .request::<Message, MessageCreate>("messages", Some(message))
            .await?
        {
            HttpResponse::Success(data) => Ok(data),
            HttpResponse::Error(err) => Err(anyhow::anyhow!("Could not send message: {:?}", err)),
        }
    }

    /// Create a [`GatewayClient`] using the connected instance's instance info
    /// pandemonium url if any.
    pub async fn create_gateway(&mut self) -> Result<GatewayClient> {
        let info = self.get_instance_info().await?;
        let gateway_url = info.pandemonium_url.clone();
        Ok(GatewayClient::new(&self.token).gateway_url(gateway_url))
    }
}
