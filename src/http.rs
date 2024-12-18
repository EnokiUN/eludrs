use crate::{models::HttpResponse, GatewayClient, REST_URL};
use anyhow::Result;
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map};
use std::{fmt::Display, str::FromStr, time::Duration};
use todel::models::{
    Category, ErrorResponse, InstanceInfo, Message, MessageCreate, MessageDisguise,
    PasswordDeleteCredentials, ResetPassword, Session, SessionCreate, SessionCreated, Sphere,
    SphereChannel, SphereType, UpdateUser, UpdateUserProfile, User, UserCreate,
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

    async fn request<T: for<'a> Deserialize<'a>, Q: Serialize + ?Sized, B: Serialize + Sized>(
        &self,
        method: &str,
        path: &str,
        query: Option<&Q>,
        body: Option<B>,
    ) -> Result<HttpResponse<T>> {
        let mut builder = self
            .client
            .request(
                Method::from_str(method)?,
                format!("{}/{}", self.rest_url, path),
            )
            .header("Authorization", &self.token);
        if let Some(body) = body {
            builder = builder.json(&body);
        }
        if let Some(query) = query {
            builder = builder.query(query);
        }
        let (client, request_res) = builder.build_split();
        let request = request_res?;
        loop {
            let request = request.try_clone().expect("Could not clone request");
            match client
                .execute(request)
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
    pub async fn send_message<C: Display>(
        &self,
        channel_id: u64,
        content: C,
        reference: Option<u64>,
    ) -> Result<Message> {
        self.send_msg(channel_id, content.to_string(), None, reference)
            .await
    }

    /// Send a message with a [`MessageDisguise`]
    pub async fn send_message_with_disguise<C: Display>(
        &self,
        channel_id: u64,
        content: C,
        disguise: MessageDisguise,
        reference: Option<u64>,
    ) -> Result<Message> {
        self.send_msg(channel_id, content.to_string(), Some(disguise), reference)
            .await
    }

    async fn send_msg(
        &self,
        channel_id: u64,
        content: String,
        disguise: Option<MessageDisguise>,
        reference: Option<u64>,
    ) -> Result<Message> {
        let message = MessageCreate {
            content,
            disguise,
            reference,
        };
        match self
            .request::<Message, (), MessageCreate>(
                "POST",
                &format!("/channels/{}/messages", channel_id),
                None,
                Some(message),
            )
            .await?
        {
            HttpResponse::Success(data) => Ok(data),
            HttpResponse::Error(err) => Err(anyhow::anyhow!("Could) not send message: {:?}", err)),
        }
    }

    /// Get messages from a channel.
    pub async fn get_messages(
        &self,
        channel_id: u64,
        before: Option<u64>,
        after: Option<u64>,
        limit: Option<u8>,
    ) -> Result<Vec<Message>> {
        let mut query = vec![];
        if let Some(before) = before {
            query.push(("before", before.to_string()));
        }
        if let Some(after) = after {
            query.push(("after", after.to_string()));
        }
        if let Some(limit) = limit {
            query.push(("limit", limit.to_string()));
        }
        match self
            .request::<Vec<Message>, Vec<(&str, String)>, ()>(
                "GET",
                &format!("channels/{}/messages", channel_id),
                Some(&query),
                None,
            )
            .await?
        {
            HttpResponse::Success(messages) => Ok(messages),
            HttpResponse::Error(err) => Err(anyhow::anyhow!("Could not get messages: {:?}", err)),
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
            .request::<SessionCreated, (), SessionCreate>(
                "POST",
                "sessions",
                None,
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
            .request::<(), (), PasswordDeleteCredentials>(
                "DELETE",
                &format!("sessions/{}", session_id),
                None,
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
            .request::<Vec<Session>, (), ()>("GET", "sessions", None, None)
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
            .request::<User, (), UserCreate>(
                "POST",
                "users",
                None,
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
            .request::<(), (), PasswordDeleteCredentials>(
                "DELETE",
                "users",
                None,
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
        match self
            .request::<User, (), ()>("GET", "users/@me", None, None)
            .await?
        {
            HttpResponse::Success(user) => Ok(user),
            HttpResponse::Error(err) => Err(anyhow::anyhow!("Could not get user: {:?}", err)),
        }
    }

    /// Update the current user.
    pub async fn update_user(&self, update: UpdateUser) -> Result<User> {
        match self
            .request::<User, (), UpdateUser>("PATCH", "users", None, Some(update))
            .await?
        {
            HttpResponse::Success(user) => Ok(user),
            HttpResponse::Error(err) => Err(anyhow::anyhow!("Could not update user: {:?}", err)),
        }
    }

    /// Update the current user's profile.
    pub async fn update_user_profile(&self, update: UpdateUserProfile) -> Result<User> {
        match self
            .request::<User, (), UpdateUserProfile>("PATCH", "users/profile", None, Some(update))
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
            .request::<User, (), ()>("GET", &format!("users/{}", user_id), None, None)
            .await?
        {
            HttpResponse::Success(user) => Ok(user),
            HttpResponse::Error(err) => Err(anyhow::anyhow!("Could not get user: {:?}", err)),
        }
    }

    /// Get a user by their username.
    pub async fn get_user_by_username(&self, username: String) -> Result<User> {
        match self
            .request::<User, (), ()>("GET", &format!("users/{}", username), None, None)
            .await?
        {
            HttpResponse::Success(user) => Ok(user),
            HttpResponse::Error(err) => Err(anyhow::anyhow!("Could not get user: {:?}", err)),
        }
    }

    /// Verify your email address.
    pub async fn verify_user(&self, code: String) -> Result<()> {
        match self
            .request::<(), [(&str, String)], ()>(
                "POST",
                "/users/verify",
                Some(&[("code", code)]),
                None,
            )
            .await?
        {
            HttpResponse::Success(_) => Ok(()),
            HttpResponse::Error(err) => Err(anyhow::anyhow!("Could not verify user: {:?}", err)),
        }
    }

    /// Resend the verification email.
    pub async fn resend_verification(&self) -> Result<()> {
        match self
            .request::<(), (), u8>("POST", "/users/resend-verification", None, None)
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
            .request::<(), (), serde_json::Value>(
                "POST",
                "/users/reset-password",
                None,
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
            .request::<(), (), ResetPassword>(
                "POST",
                "/users/reset-password",
                None,
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

    /// Get a channel by its id.
    pub async fn get_channel(&self, channel_id: u64) -> Result<SphereChannel> {
        match self
            .request::<SphereChannel, (), ()>(
                "GET",
                &format!("channels/{}", channel_id),
                None,
                None,
            )
            .await?
        {
            HttpResponse::Success(channel) => Ok(channel),
            HttpResponse::Error(err) => Err(anyhow::anyhow!("Could not get channel: {:?}", err)),
        }
    }

    /// Create a category.
    pub async fn create_category(&self, sphere_id: u64, name: String) -> Result<Category> {
        match self
            .request::<Category, (), serde_json::Value>(
                "POST",
                &format!("spheres/{}/categories", sphere_id),
                None,
                Some(json!({ "name": name })),
            )
            .await?
        {
            HttpResponse::Success(category) => Ok(category),
            HttpResponse::Error(err) => {
                Err(anyhow::anyhow!("Could not create category: {:?}", err))
            }
        }
    }

    /// Edit a category.
    pub async fn edit_category(
        &self,
        sphere_id: u64,
        category_id: u64,
        name: Option<String>,
        position: Option<u8>,
    ) -> Result<Category> {
        let mut map = Map::new();
        if let Some(name) = name {
            map.insert("name".to_string(), name.into());
        };
        if let Some(position) = position {
            map.insert("position".to_string(), position.into());
        };

        match self
            .request::<Category, (), serde_json::Value>(
                "PATCH",
                &format!("spheres/{}/categories/{}", sphere_id, category_id),
                None,
                Some(serde_json::Value::Object(map)),
            )
            .await?
        {
            HttpResponse::Success(category) => Ok(category),
            HttpResponse::Error(err) => Err(anyhow::anyhow!("Could not edit category: {:?}", err)),
        }
    }

    /// Delete a category.
    pub async fn delete_category(&self, sphere_id: u64, category_id: u64) -> Result<()> {
        match self
            .request::<(), (), ()>(
                "DELETE",
                &format!("spheres/{}/categories/{}", sphere_id, category_id),
                None,
                None,
            )
            .await?
        {
            HttpResponse::Success(_) => Ok(()),
            HttpResponse::Error(err) => {
                Err(anyhow::anyhow!("Could not delete category: {:?}", err))
            }
        }
    }

    /// Create a text channel.
    pub async fn create_text_channel(
        &self,
        sphere_id: u64,
        name: String,
        topic: Option<String>,
        category_id: Option<u64>,
    ) -> Result<SphereChannel> {
        let mut map = Map::new();
        map.insert("name".to_string(), name.into());
        map.insert("type".to_string(), "text".into());
        if let Some(topic) = topic {
            map.insert("topic".to_string(), topic.into());
        };
        if let Some(category_id) = category_id {
            map.insert("category_id".to_string(), category_id.into());
        };

        match self
            .request::<SphereChannel, (), serde_json::Value>(
                "POST",
                &format!("spheres/{}/channels", sphere_id),
                None,
                Some(serde_json::Value::Object(map)),
            )
            .await?
        {
            HttpResponse::Success(channel) => Ok(channel),
            HttpResponse::Error(err) => {
                Err(anyhow::anyhow!("Could not create text channel: {:?}", err))
            }
        }
    }

    /// Edit a text channel.
    pub async fn edit_text_channel(
        &self,
        sphere_id: u64,
        channel_id: u64,
        name: Option<String>,
        topic: Option<String>,
        position: Option<u8>,
    ) -> Result<SphereChannel> {
        let mut map = Map::new();
        if let Some(name) = name {
            map.insert("name".to_string(), name.into());
        };
        if let Some(topic) = topic {
            map.insert("topic".to_string(), topic.into());
        };
        if let Some(position) = position {
            map.insert("position".to_string(), position.into());
        };

        match self
            .request::<SphereChannel, (), serde_json::Value>(
                "PATCH",
                &format!("spheres/{}/channels/{}", sphere_id, channel_id),
                None,
                Some(serde_json::Value::Object(map)),
            )
            .await?
        {
            HttpResponse::Success(channel) => Ok(channel),
            HttpResponse::Error(err) => {
                Err(anyhow::anyhow!("Could not edit text channel: {:?}", err))
            }
        }
    }

    /// Delete a channel.
    pub async fn delete_channel(&self, sphere_id: u64, channel_id: u64) -> Result<()> {
        match self
            .request::<(), (), ()>(
                "DELETE",
                &format!("spheres/{}/channels/{}", sphere_id, channel_id),
                None,
                None,
            )
            .await?
        {
            HttpResponse::Success(_) => Ok(()),
            HttpResponse::Error(err) => Err(anyhow::anyhow!("Could not delete channel: {:?}", err)),
        }
    }

    /// Create a sphere.
    pub async fn create_sphere(
        &self,
        slug: String,
        typ: SphereType,
        description: Option<String>,
        icon: Option<u64>,
        banner: Option<u64>,
    ) -> Result<Sphere> {
        let mut map = Map::new();
        map.insert("slug".to_string(), slug.into());
        map.insert("type".to_string(), serde_json::to_value(typ)?);
        if let Some(description) = description {
            map.insert("description".to_string(), description.into());
        };
        if let Some(icon) = icon {
            map.insert("icon".to_string(), icon.into());
        };
        if let Some(banner) = banner {
            map.insert("banner".to_string(), banner.into());
        };

        match self
            .request::<Sphere, (), serde_json::Value>(
                "POST",
                "spheres",
                None,
                Some(serde_json::Value::Object(map)),
            )
            .await?
        {
            HttpResponse::Success(sphere) => Ok(sphere),
            HttpResponse::Error(err) => Err(anyhow::anyhow!("Could not create sphere: {:?}", err)),
        }
    }

    /// Get a sphere by its id.
    pub async fn get_sphere(&self, sphere_id: u64) -> Result<Sphere> {
        match self
            .request::<Sphere, (), ()>("GET", &format!("spheres/{}", sphere_id), None, None)
            .await?
        {
            HttpResponse::Success(sphere) => Ok(sphere),
            HttpResponse::Error(err) => Err(anyhow::anyhow!("Could not get sphere: {:?}", err)),
        }
    }

    /// Get a sphere by its slug.
    pub async fn get_sphere_by_slug(&self, slug: String) -> Result<Sphere> {
        match self
            .request::<Sphere, (), ()>("GET", &format!("spheres/{}", slug), None, None)
            .await?
        {
            HttpResponse::Success(sphere) => Ok(sphere),
            HttpResponse::Error(err) => Err(anyhow::anyhow!("Could not get sphere: {:?}", err)),
        }
    }

    /// Join a sphere by its id.
    pub async fn join_sphere(&self, sphere_id: u64) -> Result<()> {
        match self
            .request::<(), (), ()>("GET", &format!("spheres/{}/join", sphere_id), None, None)
            .await?
        {
            HttpResponse::Success(_) => Ok(()),
            HttpResponse::Error(err) => Err(anyhow::anyhow!("Could not join sphere: {:?}", err)),
        }
    }

    /// Join a sphere by its slug.
    pub async fn join_sphere_by_slug(&self, slug: String) -> Result<()> {
        match self
            .request::<(), (), ()>("GET", &format!("spheres/{}/join", slug), None, None)
            .await?
        {
            HttpResponse::Success(_) => Ok(()),
            HttpResponse::Error(err) => Err(anyhow::anyhow!("Could not join sphere: {:?}", err)),
        }
    }
}
