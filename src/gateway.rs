use std::{
    collections::HashMap,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    thread,
    time::Duration,
};

use anyhow::{bail, Result};
use futures::{stream::SplitStream, SinkExt, Stream, StreamExt};
use rand::{rngs::StdRng, Rng, SeedableRng};
use todel::models::{ClientPayload, ServerPayload, Sphere, User};
use tokio::{net::TcpStream, sync::Mutex, task::JoinHandle, time};
use tokio_tungstenite::{
    connect_async, tungstenite::Message as WSMessage, MaybeTlsStream, WebSocketStream,
};

use crate::{models::Event, GATEWAY_URL};

type WsReceiver = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

/// Data provided to the client from the gateway
#[derive(Default, Debug, Clone)]
pub struct GatewayData {
    user: Option<User>,
    spheres: HashMap<u64, Sphere>,
}

/// A Stream of Pandemonium events
#[derive(Debug)]
pub struct Events {
    gateway_url: String,
    token: String,
    rx: Arc<Mutex<Option<WsReceiver>>>,
    ping: Arc<Mutex<Option<JoinHandle<()>>>>,
    rng: Arc<Mutex<StdRng>>,
    data: Mutex<GatewayData>,
}

/// Simple gateway client
#[derive(Debug, Clone)]
pub struct GatewayClient {
    pub gateway_url: String,
    token: String,
}

impl GatewayClient {
    /// Create a new GatewayClient
    pub fn new(token: &str) -> GatewayClient {
        GatewayClient {
            gateway_url: GATEWAY_URL.to_string(),
            token: token.to_string(),
        }
    }

    /// Change the url of the GatewayClient
    ///
    /// # Example:
    /// ```rust
    /// use eludrs::GatewayClient;
    ///
    /// let client = GatewayClient::new().gateway_url("http://0.0.0.0:7160".to_string());
    ///
    /// assert_eq!(client.gateway_url, "http://0.0.0.0:7160".to_string())
    /// ```
    pub fn gateway_url(mut self, url: String) -> GatewayClient {
        self.gateway_url = url;
        self
    }

    /// Start a connection to the Pandemonium and return [`Events`]
    pub async fn get_events(&self) -> Result<Events> {
        let mut events = Events::new(self.gateway_url.clone(), self.token.clone());
        events.connect().await?;
        Ok(events)
    }
}

impl Events {
    fn new(gateway_url: String, token: String) -> Self {
        Self {
            gateway_url,
            token,
            rx: Arc::new(Mutex::new(None)),
            ping: Arc::new(Mutex::new(None)),
            rng: Arc::new(Mutex::new(StdRng::from_entropy())),
            // FIXME: send self to hell and make not mutex thanks
            data: Mutex::new(GatewayData::default()),
        }
    }

    async fn connect(&mut self) -> Result<()> {
        log::debug!("Events connecting");
        let mut ping = self.ping.lock().await;
        if ping.is_some() {
            ping.as_mut().unwrap().abort();
        }
        let (socket, _) = connect_async(&self.gateway_url).await?;
        let (mut tx, mut rx) = socket.split();
        loop {
            if let Some(Ok(WSMessage::Text(msg))) = rx.next().await {
                if let Ok(ServerPayload::Hello {
                    heartbeat_interval, ..
                }) = serde_json::from_str(&msg)
                {
                    if let Err(err) = tx
                        .send(WSMessage::Text(
                            serde_json::to_string(&ClientPayload::Authenticate(self.token.clone()))
                                .unwrap(),
                        ))
                        .await
                    {
                        bail!("Encountered error while authenticating {:?}", err);
                    };
                    let initial_heartbeat = self.rng.lock().await.gen_range(0..heartbeat_interval);
                    *ping = Some(tokio::spawn(async move {
                        time::sleep(Duration::from_millis(initial_heartbeat)).await;
                        loop {
                            match tx
                                .send(WSMessage::Text(
                                    serde_json::to_string(&ClientPayload::Ping).unwrap(),
                                ))
                                .await
                            {
                                Ok(_) => {
                                    time::sleep(Duration::from_millis(heartbeat_interval)).await
                                }
                                Err(err) => {
                                    log::debug!("Encountered error while pinging {:?}", err);
                                    break;
                                }
                            }
                        }
                    }));
                    break;
                }
            } else {
                bail!("Could not find HELLO payload");
            }
        }

        *self.rx.lock().await = Some(rx);
        Ok(())
    }

    async fn reconect(
        waker: Waker,
        gateway_url: String,
        token: String,
        rx: Arc<Mutex<Option<WsReceiver>>>,
        ping: Arc<Mutex<Option<JoinHandle<()>>>>,
        rng: Arc<Mutex<StdRng>>,
    ) {
        let mut wait = 1;
        let mut ping = ping.lock().await;
        if ping.is_some() {
            ping.as_mut().unwrap().abort();
        }
        'outer: loop {
            match connect_async(&gateway_url).await {
                Ok((socket, _)) => {
                    let (mut tx, mut new_rx) = socket.split();
                    loop {
                        if let Some(Ok(WSMessage::Text(msg))) = new_rx.next().await {
                            if let Ok(ServerPayload::Hello {
                                heartbeat_interval, ..
                            }) = serde_json::from_str(&msg)
                            {
                                if let Err(err) = tx
                                    .send(WSMessage::Text(
                                        serde_json::to_string(&ClientPayload::Authenticate(
                                            token.clone(),
                                        ))
                                        .unwrap(),
                                    ))
                                    .await
                                {
                                    log::error!("Encountered error while authenticating {:?}", err);
                                    continue;
                                };
                                *ping = Some(tokio::spawn(async move {
                                    time::sleep(Duration::from_millis(
                                        rng.lock().await.gen_range(0..heartbeat_interval),
                                    ))
                                    .await;
                                    loop {
                                        match tx
                                            .send(WSMessage::Text(
                                                serde_json::to_string(&ClientPayload::Ping)
                                                    .unwrap(),
                                            ))
                                            .await
                                        {
                                            Ok(_) => {
                                                time::sleep(Duration::from_millis(
                                                    heartbeat_interval,
                                                ))
                                                .await
                                            }
                                            Err(err) => {
                                                log::debug!(
                                                    "Encountered error while pinging {:?}",
                                                    err
                                                );
                                                break;
                                            }
                                        }
                                    }
                                }));
                                break;
                            }
                        } else {
                            log::error!("Could not find HELLO payload");
                            continue 'outer;
                        }
                    }

                    *rx.lock().await = Some(new_rx);
                    log::debug!("Reconnected to websocket");
                    break;
                }
                Err(err) => {
                    log::info!(
                        "Websocket reconnection failed {}, trying again in {}s",
                        err,
                        wait
                    );
                    thread::sleep(Duration::from_secs(wait));
                    if wait < 64 {
                        wait *= 2;
                    }
                }
            }
        }
        waker.wake();
    }
}

impl Stream for Events {
    type Item = Event;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let mut data = futures::executor::block_on(async { self.data.lock().await });
            let mut rx = futures::executor::block_on(async { self.rx.lock().await });
            if rx.is_some() {
                match rx.as_mut().unwrap().poll_next_unpin(cx) {
                    Poll::Ready(Some(Ok(msg))) => match msg {
                        WSMessage::Text(msg) => {
                            if let Ok(payload) = serde_json::from_str(&msg) {
                                match payload {
                                    ServerPayload::Pong
                                    | ServerPayload::RateLimit { .. }
                                    | ServerPayload::Hello { .. } => {}
                                    ServerPayload::Authenticated { user, spheres } => {
                                        data.user = Some(user);
                                        spheres.into_iter().for_each(|s| {
                                            data.spheres.insert(s.id, s);
                                        });
                                        break Poll::Ready(Some(Event::Authenticated));
                                    }
                                    ServerPayload::MessageCreate(msg) => {
                                        break Poll::Ready(Some(Event::Message(msg)));
                                    }
                                    ServerPayload::UserUpdate(user) => {
                                        break Poll::Ready(Some(Event::UserUpdate(user)));
                                    }
                                    ServerPayload::PresenceUpdate { status, user_id } => {
                                        break Poll::Ready(Some(Event::PresenceUpdate {
                                            user_id,
                                            status,
                                        }));
                                    }
                                    ServerPayload::SphereJoin(sphere) => {
                                        break Poll::Ready(Some(Event::SphereJoin(sphere)));
                                    }
                                    ServerPayload::SphereMemberJoin { user, sphere_id } => {
                                        break Poll::Ready(Some(Event::SphereMemberJoin {
                                            user,
                                            sphere_id,
                                        }));
                                    }
                                    ServerPayload::CategoryCreate {
                                        category,
                                        sphere_id,
                                    } => {
                                        break Poll::Ready(Some(Event::CategoryCreate {
                                            category,
                                            sphere_id,
                                        }));
                                    }
                                    ServerPayload::CategoryEdit {
                                        data,
                                        category_id,
                                        sphere_id,
                                    } => {
                                        break Poll::Ready(Some(Event::CategoryEdit {
                                            data,
                                            category_id,
                                            sphere_id,
                                        }));
                                    }
                                    ServerPayload::CategoryDelete {
                                        category_id,
                                        sphere_id,
                                    } => {
                                        break Poll::Ready(Some(Event::CategoryDelete {
                                            category_id,
                                            sphere_id,
                                        }));
                                    }
                                    ServerPayload::SphereChannelCreate { channel, sphere_id } => {
                                        break Poll::Ready(Some(Event::SphereChannelCreate {
                                            channel,
                                            sphere_id,
                                        }));
                                    }
                                    ServerPayload::SphereChannelEdit {
                                        data,
                                        channel_id,
                                        sphere_id,
                                    } => {
                                        break Poll::Ready(Some(Event::SphereChannelEdit {
                                            data,
                                            channel_id,
                                            sphere_id,
                                        }));
                                    }
                                    ServerPayload::SphereChannelDelete {
                                        channel_id,
                                        sphere_id,
                                    } => {
                                        break Poll::Ready(Some(Event::SphereChannelDelete {
                                            channel_id,
                                            sphere_id,
                                        }));
                                    }
                                }
                            }
                        }
                        WSMessage::Close(_) => {
                            log::debug!("Websocket closed, reconnecting");
                            tokio::spawn(Events::reconect(
                                cx.waker().clone(),
                                self.gateway_url.clone(),
                                self.token.clone(),
                                Arc::clone(&self.rx),
                                Arc::clone(&self.ping),
                                Arc::clone(&self.rng),
                            ));
                            return Poll::Pending;
                        }
                        _ => {}
                    },
                    Poll::Pending => break Poll::Pending,
                    Poll::Ready(None) => {
                        log::debug!("Websocket closed, reconnecting");
                        tokio::spawn(Events::reconect(
                            cx.waker().clone(),
                            self.gateway_url.clone(),
                            self.token.clone(),
                            Arc::clone(&self.rx),
                            Arc::clone(&self.ping),
                            Arc::clone(&self.rng),
                        ));
                        return Poll::Pending;
                    }
                    _ => {}
                }
            }
        }
    }
}
