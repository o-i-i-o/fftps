//! 应用壳：tab 导航、连接管理、日志订阅桥接
//!
//! - 启动即连接 fftpd；断线后按指数退避（1~10s）自动重连；
//! - 底部状态栏显示连接状态与 IPC 端点，断线时写操作按钮禁用；
//! - 日志页经 [`iced::Subscription`] + [`iced::stream::channel`] 桥接
//!   `tokio::sync::broadcast::Receiver`，把服务端推送转成界面消息。

use fftp_ipc::protocol::{Command, Event};
use iced::futures::SinkExt;
use iced::widget::{button, column, container, row, text};
use iced::{Color, Element, Length, Subscription, Task};
use tokio::sync::broadcast::error::RecvError;

use crate::ipc_service::{self, ConnState, InitialState, IpcConn, IpcError, IpcService, ServerStatus};
use crate::tabs::{about, file_logs, logs, security, server, service, users};

/// 顶部导航的 tab
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Tab {
    /// 服务器（运行状态 + `config.toml` 表单/原文）
    #[default]
    Server,
    /// 用户（`users.json` 管理）
    Users,
    /// 安全（`[security]` 段 + 审计）
    Security,
    /// 日志（实时订阅 + 文件历史）
    Logs,
    /// 文件日志（文件操作审计）
    FileLogs,
    /// 服务（启停重启 + 日志设置）
    Service,
    /// 关于
    About,
}

impl Tab {
    /// 全部 tab（导航顺序）
    pub const ALL: [Tab; 7] = [
        Tab::Server,
        Tab::Users,
        Tab::Security,
        Tab::Logs,
        Tab::FileLogs,
        Tab::Service,
        Tab::About,
    ];

    /// 导航标题
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Tab::Server => "服务器",
            Tab::Users => "用户",
            Tab::Security => "安全",
            Tab::Logs => "日志",
            Tab::FileLogs => "文件日志",
            Tab::Service => "服务",
            Tab::About => "关于",
        }
    }
}

/// 全局消息
#[derive(Debug, Clone)]
pub enum Message {
    /// 切换 tab
    SelectTab(Tab),
    /// 连接建立/失败（首连与重连共用）
    ConnectFinished(Result<IpcConn, String>),
    /// 退避计时到，再次尝试连接
    RetryConnect,
    /// 子页请求发现连接断开
    ConnectionLost(String),
    /// 日志订阅流因断线结束（附订阅所在的连接代数）
    LogStreamEnded(u64),
    /// `GetInitialState` 响应
    InitialState(Result<InitialState, IpcError>),
    /// 服务页状态轮询触发（5s 间隔）
    PollStatus,
    /// 无副作用占位（fire-and-forget 任务）
    Ignored,
    /// 服务器页消息
    Server(server::Msg),
    /// 用户页消息
    Users(users::Msg),
    /// 安全页消息
    Security(security::Msg),
    /// 日志页消息
    Logs(logs::Msg),
    /// 文件日志页消息
    FileLogs(file_logs::Msg),
    /// 服务页消息
    Service(service::Msg),
}

/// 应用状态
#[derive(Debug, Default)]
pub struct App {
    ipc: IpcService,
    tab: Tab,
    server: server::ServerTab,
    users: users::UsersTab,
    security: security::SecurityTab,
    logs: logs::LogsTab,
    file_logs: file_logs::FileLogsTab,
    service: service::ServiceTab,
    /// 状态栏提示（非页面级错误）
    notice: Option<String>,
}

impl App {
    /// 初始状态 + 启动即连接
    pub fn init() -> (Self, Task<Message>) {
        let mut app = Self::default();
        let task = app.start_connect();
        (app, task)
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::SelectTab(tab) => self.select_tab(tab),
            Message::ConnectFinished(result) => self.on_connect(result),
            Message::RetryConnect => self.start_connect(),
            Message::ConnectionLost(reason) => self.on_disconnected(reason),
            Message::LogStreamEnded(generation) => {
                if generation == self.ipc.generation() {
                    self.on_disconnected("连接已断开".to_owned())
                } else {
                    Task::none()
                }
            }
            Message::InitialState(result) => self.on_initial_state(result),
            Message::PollStatus => self.service.update(service::Msg::RefreshStatus, &self.ipc),
            Message::Ignored => Task::none(),
            Message::Server(m) => self.server.update(m, &self.ipc),
            Message::Users(m) => self.users.update(m, &self.ipc),
            Message::Security(m) => self.security.update(m, &self.ipc),
            Message::Logs(m) => self.logs.update(m, &self.ipc),
            Message::FileLogs(m) => self.file_logs.update(m, &self.ipc),
            Message::Service(m) => self.service.update(m, &self.ipc),
        }
    }

    /// 发起一次连接（首连或重连）
    fn start_connect(&mut self) -> Task<Message> {
        self.ipc.mark_connecting();
        Task::perform(ipc_service::connect(), Message::ConnectFinished)
    }

    fn on_connect(&mut self, result: Result<IpcConn, String>) -> Task<Message> {
        match result {
            Ok(conn) => {
                self.ipc.mark_connected(conn.clone());
                self.notice = None;
                // 连接成功后拉取一次数据刷新各页，并载入当前页数据
                let tab = self.tab;
                Task::batch([
                    Task::perform(
                        ipc_service::request::<ServerStatus>(conn.clone(), Command::GetStatus),
                        |r| Message::Server(server::Msg::Status(r)),
                    ),
                    Task::perform(
                        ipc_service::request::<InitialState>(conn, Command::GetInitialState),
                        Message::InitialState,
                    ),
                    Self::enter_tab(tab),
                ])
            }
            Err(reason) => {
                self.ipc.mark_disconnected(reason);
                self.schedule_reconnect()
            }
        }
    }

    fn on_initial_state(&mut self, result: Result<InitialState, IpcError>) -> Task<Message> {
        match result {
            Ok(state) => Task::batch([
                Task::done(Message::Server(server::Msg::Content(state.config))),
                Task::done(Message::Users(users::Msg::Content(state.users))),
            ]),
            Err(e) => self.on_request_error(&e),
        }
    }

    fn on_request_error(&mut self, err: &IpcError) -> Task<Message> {
        if err.is_disconnected() {
            self.on_disconnected(err.message().to_owned())
        } else {
            self.notice = Some(err.message().to_owned());
            Task::none()
        }
    }

    /// 连接断开：更新状态并调度退避重连（重复信号忽略）
    fn on_disconnected(&mut self, reason: String) -> Task<Message> {
        if !self.ipc.is_connected() {
            return Task::none();
        }
        self.ipc.mark_disconnected(reason.clone());
        self.notice = Some(reason);
        self.schedule_reconnect()
    }

    fn schedule_reconnect(&mut self) -> Task<Message> {
        let delay = self.ipc.next_backoff();
        Task::perform(
            async move {
                tokio::time::sleep(delay).await;
            },
            |()| Message::RetryConnect,
        )
    }

    fn select_tab(&mut self, tab: Tab) -> Task<Message> {
        let previous = self.tab;
        self.tab = tab;
        let mut tasks = Vec::new();
        if previous == Tab::Logs && tab != Tab::Logs {
            // 离开日志页：取消服务端日志订阅
            if let Some(conn) = self.ipc.conn().cloned() {
                tasks.push(Task::perform(
                    async move {
                        ipc_service::request::<serde_json::Value>(conn, Command::UnsubscribeLogs)
                            .await
                    },
                    |_| Message::Ignored,
                ));
            }
        }
        tasks.push(Self::enter_tab(tab));
        Task::batch(tasks)
    }

    /// 进入 tab 时触发该页数据载入（服务器/用户页由 `GetInitialState` 覆盖）
    fn enter_tab(tab: Tab) -> Task<Message> {
        match tab {
            Tab::Server | Tab::Users | Tab::About => Task::none(),
            Tab::Security => Task::done(Message::Security(security::Msg::Reload)),
            Tab::Logs => Task::done(Message::Logs(logs::Msg::RefreshFiles)),
            Tab::FileLogs => Task::done(Message::FileLogs(file_logs::Msg::Refresh)),
            Tab::Service => Task::batch([
                Task::done(Message::Service(service::Msg::Reload)),
                Task::done(Message::Service(service::Msg::RefreshStatus)),
            ]),
        }
    }

    /// 日志订阅桥 + 服务页状态轮询
    ///
    /// 日志订阅身份 =（"log-stream", 连接代数）：重连后代数变化自动换新流，
    /// 离开日志页或断线后不再返回该订阅，`iced` 会回收旧流；
    /// 服务页在连接期间以 5s 间隔轮询 `GetStatus` 刷新运行状态。
    fn subscription(&self) -> Subscription<Message> {
        Subscription::batch([self.log_stream_subscription(), self.poll_subscription()])
    }

    /// 服务页状态轮询（仅服务页且已连接时）
    fn poll_subscription(&self) -> Subscription<Message> {
        if self.tab != Tab::Service || !self.ipc.is_connected() {
            return Subscription::none();
        }
        iced::time::every(std::time::Duration::from_secs(5)).map(|_| Message::PollStatus)
    }

    /// 日志订阅桥：进入日志页且已连接时启动
    fn log_stream_subscription(&self) -> Subscription<Message> {
        if self.tab != Tab::Logs {
            return Subscription::none();
        }
        let Some(conn) = self.ipc.conn().cloned() else {
            return Subscription::none();
        };
        let generation = self.ipc.generation();
        Subscription::run_with_id(
            ("log-stream", generation),
            iced::stream::channel(256, move |mut output| async move {
                let client = &conn.0;
                // 先订阅事件再请求订阅，保证服务端补推的历史日志不丢失
                let mut rx = client.subscribe_events();
                if let Err(e) = client
                    .request(Command::SubscribeLogs { tail_count: 200 })
                    .await
                {
                    let err = ipc_service::map_error(e);
                    if err.is_disconnected() {
                        let _ = output.send(Message::LogStreamEnded(generation)).await;
                        return;
                    }
                    let _ = output
                        .send(Message::Logs(logs::Msg::SubscribeFailed(err)))
                        .await;
                }
                loop {
                    match rx.recv().await {
                        Ok(Event::Log { entry }) => {
                            if output.send(Message::Logs(logs::Msg::Entry(entry))).await.is_err() {
                                return;
                            }
                        }
                        Err(RecvError::Lagged(count)) => {
                            if output.send(Message::Logs(logs::Msg::Lagged(count))).await.is_err() {
                                return;
                            }
                        }
                        Err(RecvError::Closed) => break,
                    }
                }
                let _ = output.send(Message::LogStreamEnded(generation)).await;
            }),
        )
    }

    fn view(&self) -> Element<'_, Message> {
        let nav = row(Tab::ALL.iter().map(|tab| {
            let active = *tab == self.tab;
            Element::from(
                button(text(tab.title()))
                    .on_press_maybe((!active).then_some(Message::SelectTab(*tab)))
                    .style(if active {
                        button::primary
                    } else {
                        button::secondary
                    }),
            )
        }))
        .spacing(8)
        .padding(12);

        let content: Element<'_, Message> = match self.tab {
            Tab::Server => self.server.view(self.ipc.is_connected()),
            Tab::Users => self.users.view(self.ipc.is_connected()),
            Tab::Security => self.security.view(self.ipc.is_connected()),
            Tab::Logs => self.logs.view(),
            Tab::FileLogs => self.file_logs.view(self.ipc.is_connected()),
            Tab::Service => self.service.view(self.ipc.is_connected(), self.server.status()),
            Tab::About => about::view(self.server.status()),
        };

        column![
            nav,
            container(content)
                .width(Length::Fill)
                .height(Length::Fill)
                .padding(12),
            self.status_bar(),
        ]
        .into()
    }

    /// 底部状态栏：连接状态 / IPC 端点 / 提示
    fn status_bar(&self) -> Element<'_, Message> {
        let color = match self.ipc.state() {
            ConnState::Connecting => Color::from_rgb8(210, 153, 34),
            ConnState::Connected => Color::from_rgb8(46, 160, 67),
            ConnState::Disconnected(_) => Color::from_rgb8(248, 81, 73),
        };
        let notice = self.notice.clone().unwrap_or_default();
        container(
            row![
                text("连接状态：").size(12),
                text(self.ipc.state().label()).size(12).color(color),
                text(format!(
                    "IPC 端点：{}",
                    fftp_ipc::transport::endpoint_display()
                ))
                .size(12),
                text(notice).size(12).color(Color::from_rgb8(248, 81, 73)),
            ]
            .spacing(16)
            .padding(12),
        )
        .style(container::rounded_box)
        .into()
    }
}

/// `iced` update 入口
pub fn update(app: &mut App, message: Message) -> Task<Message> {
    app.update(message)
}

/// `iced` view 入口
pub fn view(app: &App) -> Element<'_, Message> {
    app.view()
}

/// `iced` subscription 入口
pub fn subscription(app: &App) -> Subscription<Message> {
    app.subscription()
}
