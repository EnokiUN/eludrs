use crate::{models::HttpResponse, GatewayClient, REST_URL};
use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{fmt::Display, time::Duration};
use todel::{
    ErrorResponse, InstanceInfo, Message, MessageCreate, MessageDisguise,
    PasswordDeleteCredentials, ResetPassword, Session, SessionCreate, SessionCreated, UpdateUser,
    UpdateUserProfile, User, UserCreate,
};
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
        method: &str,
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
            .request::<Message, MessageCreate>("POST", "messages", Some(message))
            .await?
        {
            HttpResponse::Success(data) => Ok(data),
            HttpResponse::Error(err) => Err(anyhow::anyhow!("Could not send message: {:?}", err)),
        }
    }

    /// Send a message with a disguise
    pub async fn send_message_with_disguise<C: Display>(
        &self,
        content: C,
        disguise: MessageDisguise,
    ) -> Result<Message> {
        let message = MessageCreate {
            content: content.to_string(),
            disguise: Some(disguise),
        };
        match self
            .request::<Message, MessageCreate>("POST", "messages", Some(message))
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

    /// Create a session.
    pub async fn create_session(
        &self,
        identifier: String,
        password: String,
        platform: String,
        client: String,
    ) -> Result<SessionCreated> {
        match self
            .request::<SessionCreated, SessionCreate>(
                "POST",
                "sessions",
                Some(SessionCreate {
                    identifier,
                    password,
                    platform,
                    client,
                }),
            )
            .await?
        {
            HttpResponse::Success(session) => Ok(session),
            HttpResponse::Error(err) => Err(anyhow::anyhow!("Could not create session: {:?}", err)),
        }
    }

    /// Delete a session.
    pub async fn delete_session(&self, session_id: u64, password: String) -> Result<()> {
        match self
            .request::<(), PasswordDeleteCredentials>(
                "DELETE",
                &format!("sessions/{}", session_id),
                Some(PasswordDeleteCredentials { password }),
            )
            .await?
        {
            HttpResponse::Success(_) => Ok(()),
            HttpResponse::Error(err) => Err(anyhow::anyhow!("Could not delete session: {:?}", err)),
        }
    }

    /// Get all sessions.
    pub async fn get_sessions(&self) -> Result<Vec<Session>> {
        match self
            .request::<Vec<Session>, ()>("GET", "sessions", None)
            .await?
        {
            HttpResponse::Success(sessions) => Ok(sessions),
            HttpResponse::Error(err) => Err(anyhow::anyhow!("Could not get sessions: {:?}", err)),
        }
    }

    /// Create a user.
    pub async fn create_user(
        &self,
        username: String,
        email: String,
        password: String,
    ) -> Result<User> {
        match self
            .request::<User, UserCreate>(
                "POST",
                "users",
                Some(UserCreate {
                    username,
                    email,
                    password,
                }),
            )
            .await?
        {
            HttpResponse::Success(user) => Ok(user),
            HttpResponse::Error(err) => Err(anyhow::anyhow!("Could not create user: {:?}", err)),
        }
    }

    /// Delete the current user.
    pub async fn delete_user(&self, password: String) -> Result<()> {
        match self
            .request::<(), PasswordDeleteCredentials>(
                "DELETE",
                "users",
                Some(PasswordDeleteCredentials { password }),
            )
            .await?
        {
            HttpResponse::Success(_) => Ok(()),
            HttpResponse::Error(err) => Err(anyhow::anyhow!("Could not delete user: {:?}", err)),
        }
    }

    /// Get the current user.
    pub async fn get_user(&self) -> Result<User> {
        match self.request::<User, ()>("GET", "users/@me", None).await? {
            HttpResponse::Success(user) => Ok(user),
            HttpResponse::Error(err) => Err(anyhow::anyhow!("Could not get user: {:?}", err)),
        }
    }

    /// Update the current user.
    pub async fn update_user(&self, update: UpdateUser) -> Result<User> {
        match self
            .request::<User, UpdateUser>("PATCH", "users", Some(update))
            .await?
        {
            HttpResponse::Success(user) => Ok(user),
            HttpResponse::Error(err) => Err(anyhow::anyhow!("Could not update user: {:?}", err)),
        }
    }

    /// Update the current user's profile.
    pub async fn update_user_profile(&self, update: UpdateUserProfile) -> Result<User> {
        match self
            .request::<User, UpdateUserProfile>("PATCH", "users/profile", Some(update))
            .await?
        {
            HttpResponse::Success(user) => Ok(user),
            HttpResponse::Error(err) => {
                Err(anyhow::anyhow!("Could not update user profile: {:?}", err))
            }
        }
    }

    /// Get a user by their id.
    pub async fn get_user_by_id(&self, user_id: u64) -> Result<User> {
        match self
            .request::<User, ()>("GET", &format!("users/{}", user_id), None)
            .await?
        {
            HttpResponse::Success(user) => Ok(user),
            HttpResponse::Error(err) => Err(anyhow::anyhow!("Could not get user: {:?}", err)),
        }
    }

    /// Get a user by their username.
    pub async fn get_user_by_username(&self, username: String) -> Result<User> {
        match self
            .request::<User, ()>("GET", &format!("users/{}", username), None)
            .await?
        {
            HttpResponse::Success(user) => Ok(user),
            HttpResponse::Error(err) => Err(anyhow::anyhow!("Could not get user: {:?}", err)),
        }
    }

    /// Verify your email address.
    pub async fn verify_user(&self, code: String) -> Result<()> {
        match self
            .request::<(), u8>("POST", &format!("/users/verify?{code}"), None)
            .await?
        {
            HttpResponse::Success(_) => Ok(()),
            HttpResponse::Error(err) => Err(anyhow::anyhow!("Could not verify user: {:?}", err)),
        }
    }

    /// Resend the verification email.
    pub async fn resend_verification(&self) -> Result<()> {
        match self
            .request::<(), u8>("POST", "/users/resend-verification", None)
            .await?
        {
            HttpResponse::Success(_) => Ok(()),
            HttpResponse::Error(err) => Err(anyhow::anyhow!(
                "Could not resend verification email: {:?}",
                err
            )),
        }
    }

    /// Create password reset code.
    pub async fn create_password_reset(&self, email: String) -> Result<()> {
        match self
            .request::<(), serde_json::Value>(
                "POST",
                "/users/reset-password",
                Some(json!({ "email": email })),
            )
            .await?
        {
            HttpResponse::Success(_) => Ok(()),
            HttpResponse::Error(err) => Err(anyhow::anyhow!(
                "Could not create password reset code: {:?}",
                err
            )),
        }
    }

    /// Reset your password.
    pub async fn reset_password(&self, code: u32, email: String, password: String) -> Result<()> {
        match self
            .request::<(), ResetPassword>(
                "POST",
                "/users/reset-password",
                Some(ResetPassword {
                    code,
                    email,
                    password,
                }),
            )
            .await?
        {
            HttpResponse::Success(_) => Ok(()),
            HttpResponse::Error(err) => Err(anyhow::anyhow!("Could not reset password: {:?}", err)),
        }
    }
}
