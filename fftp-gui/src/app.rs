//! 应用壳：连接监督、页面切换、日志流桥接
//!
//! - 启动即连接 fftpd；断线后按指数退避（1~10s）自动重连；
//! - 底部状态栏显示连接状态与 IPC 端点，断线时写操作按钮禁用；
//! - 进入日志页时派发桥接任务：先订阅本地事件广播、再请求服务端
//!   `SubscribeLogs`（保证补推历史不丢），推送经事件循环写回 UI 模型。
//!
//! 线程模型：UI 状态只允许在事件循环线程变更。tokio 任务的回传一律经
//! [`slint::Weak::upgrade_in_event_loop`]；可变共享状态收敛在
//! [`Core`]（`Send`）内，UI 线程与 tokio 任务均经 `Mutex` 短临界区访问，
//! 锁内不做 IO、不调用其他持锁路径。

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::sync::{Arc, Mutex};

use fftp_common::users::User;
use fftp_ipc::protocol::{Command, Event, FileOpLogEntry, LogEntry};
use slint::ComponentHandle;
use tokio::sync::broadcast::error::RecvError;

use crate::ipc_service::{self, InitialState, IpcConn, IpcError, IpcService, ServerStatus};
use crate::tabs::{about, file_logs, logs, security, server, service, users, FileOption};
use crate::{
    AppWindow, AppState, FileLogsState, LogsState, SecurityState, ServerState, ServiceState,
    UsersState,
};

/// 全局共享状态句柄
pub type SharedCore = Arc<Mutex<Core>>;

/// UI 弱句柄（tokio 任务的回传入口）
pub type UiWeak = slint::Weak<AppWindow>;

fn color_connected() -> slint::Color {
    slint::Color::from_rgb_u8(46, 160, 67)
}

fn color_connecting() -> slint::Color {
    slint::Color::from_rgb_u8(210, 153, 34)
}

fn color_disconnected() -> slint::Color {
    slint::Color::from_rgb_u8(248, 81, 73)
}

/// 应用共享状态（`Send`）：连接记账、跨页数据与日志流控制
pub struct Core {
    /// IPC 连接管理与状态记账
    pub ipc: IpcService,
    /// tokio 运行时句柄（派发异步请求）
    pub rt: tokio::runtime::Handle,
    /// 本地用户表（用户页展示与重名校验）
    pub users: BTreeMap<String, User>,
    /// 实时日志环形缓冲（重建过滤视图的数据源）
    pub logs_live: VecDeque<LogEntry>,
    /// 历史文件日志条目
    pub logs_file_entries: Vec<LogEntry>,
    /// 日志文件列表
    pub logs_files: Vec<FileOption>,
    /// 当前选中的日志文件
    pub logs_selected: Option<FileOption>,
    /// 审计日志文件列表
    pub filelog_files: Vec<FileOption>,
    /// 当前选中的审计日志文件
    pub filelog_selected: Option<FileOption>,
    /// 审计日志条目
    pub filelog_entries: Vec<FileOpLogEntry>,
    /// 日志流桥接任务句柄（离开日志页/断线时中止）
    pub log_abort: Option<tokio::task::AbortHandle>,
    /// 建议主目录候选（缩写展示文本 → 完整路径）
    pub suggestion_map: Vec<(String, String)>,
}

impl Core {
    #[must_use]
    pub fn new(rt: tokio::runtime::Handle) -> Self {
        Self {
            ipc: IpcService::default(),
            rt,
            users: BTreeMap::new(),
            logs_live: VecDeque::new(),
            logs_file_entries: Vec::new(),
            logs_files: Vec::new(),
            logs_selected: None,
            filelog_files: Vec::new(),
            filelog_selected: None,
            filelog_entries: Vec::new(),
            log_abort: None,
            suggestion_map: Vec::new(),
        }
    }
}

/// 把异步请求派发到 tokio 运行时，完成后回 UI 线程执行 `on_done`
pub fn dispatch<T, F>(
    weak: UiWeak,
    core: &SharedCore,
    fut: impl Future<Output = T> + Send + 'static,
    on_done: F,
) where
    T: Send + 'static,
    F: FnOnce(&AppWindow, &SharedCore, T) + Send + 'static,
{
    let rt = core.lock().unwrap().rt.clone();
    let core = core.clone();
    rt.spawn(async move {
        let result = fut.await;
        let _ = weak.upgrade_in_event_loop(move |ui| on_done(&ui, &core, result));
    });
}

/// 把 `fn(&AppWindow, &SharedCore)` 包装为无参 Slint 回调
pub fn wire0(
    weak: &UiWeak,
    core: &SharedCore,
    f: fn(&AppWindow, &SharedCore),
) -> impl FnMut() + 'static {
    let weak = weak.clone();
    let core = core.clone();
    move || {
        if let Some(ui) = weak.upgrade() {
            f(&ui, &core);
        }
    }
}

/// 把 `fn(&AppWindow, &SharedCore, A)` 包装为单参 Slint 回调
pub fn wire1<A: 'static>(
    weak: &UiWeak,
    core: &SharedCore,
    f: fn(&AppWindow, &SharedCore, A),
) -> impl FnMut(A) + 'static {
    let weak = weak.clone();
    let core = core.clone();
    move |a| {
        if let Some(ui) = weak.upgrade() {
            f(&ui, &core, a);
        }
    }
}

/// 把 `fn(&AppWindow, &SharedCore, A, B)` 包装为双参 Slint 回调
pub fn wire2<A: 'static, B: 'static>(
    weak: &UiWeak,
    core: &SharedCore,
    f: fn(&AppWindow, &SharedCore, A, B),
) -> impl FnMut(A, B) + 'static {
    let weak = weak.clone();
    let core = core.clone();
    move |a, b| {
        if let Some(ui) = weak.upgrade() {
            f(&ui, &core, a, b);
        }
    }
}

/// 初始属性与全部回调接线
pub fn wire(ui: &AppWindow, core: &SharedCore) {
    let weak = ui.as_weak();

    // 底部状态栏与关于页的本地回退信息
    let app = ui.global::<AppState>();
    app.set_connected(false);
    app.set_conn_label("连接中…".into());
    app.set_conn_color(color_connecting());
    app.set_endpoint(fftp_ipc::transport::endpoint_display().into());
    app.set_notice("".into());
    about::set_fallback(ui);
    ui.global::<ServiceState>()
        .set_hint(service::platform_hint().into());

    // 页面切换：离开日志页时退订日志流，进入新页时载入数据
    app.on_select_tab(wire1(&weak, core, |ui, core, tab: i32| {
        let previous = ui.global::<AppState>().get_current_tab();
        ui.global::<AppState>().set_current_tab(tab);
        if previous == 3 && tab != 3 {
            stop_log_stream(core);
        }
        enter_tab(ui, core, tab);
    }));

    server::wire(&weak, core);
    users::wire(&weak, core);
    security::wire(&weak, core);
    logs::wire(&weak, core);
    file_logs::wire(&weak, core);
    service::wire(&weak, core);

    start_status_poll(weak.clone(), core.clone());
}

/// 进入页面时触发数据载入（服务器/用户页由 `GetInitialState` 覆盖）
fn enter_tab(ui: &AppWindow, core: &SharedCore, tab: i32) {
    match tab {
        2 => security::reload(ui, core),
        3 => {
            logs::refresh_files(ui, core);
            start_log_stream(ui.as_weak(), core);
        }
        4 => file_logs::refresh(ui, core),
        5 => {
            service::reload_log(ui, core);
            request_status(ui, core);
        }
        _ => {}
    }
}

/// 服务页 5 秒轮询：仅服务页且已连接时刷新运行状态
fn start_status_poll(weak: UiWeak, core: SharedCore) {
    let rt = core.lock().unwrap().rt.clone();
    rt.spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            let w = weak.clone();
            let c = core.clone();
            let _ = w.upgrade_in_event_loop(move |ui| {
                let app = ui.global::<AppState>();
                if app.get_current_tab() == 5 && app.get_connected() {
                    request_status(&ui, &c);
                }
            });
        }
    });
}

/// 应用启动时的首次连接（自 tokio 任务上下文切入 UI 线程）
pub fn start_connect(weak: &UiWeak, core: &SharedCore) {
    let _ = weak.clone().upgrade_in_event_loop({
        let core = core.clone();
        move |ui| begin_connect(&ui, &core)
    });
}

/// 发起一次连接（首连与重连共用）
fn begin_connect(ui: &AppWindow, core: &SharedCore) {
    core.lock().unwrap().ipc.mark_connecting();
    let app = ui.global::<AppState>();
    app.set_conn_label("连接中…".into());
    app.set_conn_color(color_connecting());
    dispatch(ui.as_weak(), core, ipc_service::connect(), handle_connect);
}

/// 连接结果：成功后刷新各页数据，失败进入退避重连
fn handle_connect(ui: &AppWindow, core: &SharedCore, result: Result<IpcConn, String>) {
    let conn = match result {
        Ok(conn) => conn,
        Err(reason) => {
            core.lock().unwrap().ipc.mark_disconnected(reason.clone());
            set_conn_state(ui, false, color_disconnected());
            ui.global::<AppState>().set_notice(reason.into());
            set_pages_connected(ui, false);
            schedule_reconnect(ui.as_weak(), core);
            return;
        }
    };
    {
        let mut c = core.lock().unwrap();
        c.ipc.mark_connected(conn.clone());
    }
    set_conn_state(ui, true, color_connected());
    ui.global::<AppState>().set_notice("".into());
    set_pages_connected(ui, true);

    dispatch(
        ui.as_weak(),
        core,
        async move { ipc_service::request::<InitialState>(conn, Command::GetInitialState).await },
        handle_initial,
    );
    request_status(ui, core);
    let tab = ui.global::<AppState>().get_current_tab();
    enter_tab(ui, core, tab);
}

/// `GetInitialState` 响应：服务器页表单 + 用户页列表
fn handle_initial(ui: &AppWindow, core: &SharedCore, result: Result<InitialState, IpcError>) {
    match result {
        Ok(state) => {
            server::apply_content(ui, &state.config);
            users::load(ui, core, &state.users);
        }
        Err(e) => {
            if !relay(ui, core, &e) {
                ui.global::<AppState>().set_notice(e.message().into());
            }
        }
    }
}

/// 拉取运行状态（服务器/服务/关于页共用；连接成功与 5s 轮询触发）
pub fn request_status(ui: &AppWindow, core: &SharedCore) {
    let conn = {
        let c = core.lock().unwrap();
        c.ipc.conn().cloned()
    };
    let Some(conn) = conn else {
        return;
    };
    dispatch(
        ui.as_weak(),
        core,
        async move { ipc_service::request::<ServerStatus>(conn, Command::GetStatus).await },
        on_status,
    );
}

/// `GetStatus` 响应：刷新服务器页/服务页状态卡与关于页
fn on_status(ui: &AppWindow, core: &SharedCore, result: Result<ServerStatus, IpcError>) {
    match result {
        Ok(status) => {
            server::set_status(ui, &status);
            service::set_status(ui, &status);
            about::set_from_status(ui, &status);
        }
        Err(e) => {
            // 轮询场景下的业务错误静默；断线触发全局重连
            relay(ui, core, &e);
        }
    }
}

/// 页面错误中转：断线错误触发全局断线处理；返回是否为断线
pub fn relay(ui: &AppWindow, core: &SharedCore, err: &IpcError) -> bool {
    if err.is_disconnected() {
        handle_disconnect(ui, core, err.message().to_owned());
        true
    } else {
        false
    }
}

/// 连接断开：更新状态并调度退避重连（重复信号忽略）
pub fn handle_disconnect(ui: &AppWindow, core: &SharedCore, reason: String) {
    {
        let mut c = core.lock().unwrap();
        if !c.ipc.is_connected() {
            return;
        }
        c.ipc.mark_disconnected(reason.clone());
        stop_log_stream_locked(&mut c);
    }
    set_conn_state(ui, false, color_disconnected());
    ui.global::<AppState>().set_notice(reason.into());
    set_pages_connected(ui, false);
    schedule_reconnect(ui.as_weak(), core);
}

/// 退避计时到，再次尝试连接
fn schedule_reconnect(weak: UiWeak, core: &SharedCore) {
    let (delay, rt) = {
        let mut c = core.lock().unwrap();
        (c.ipc.next_backoff(), c.rt.clone())
    };
    let core = core.clone();
    rt.spawn(async move {
        tokio::time::sleep(delay).await;
        let _ = weak.upgrade_in_event_loop(move |ui| begin_connect(&ui, &core));
    });
}

/// 同步底部状态栏
fn set_conn_state(ui: &AppWindow, connected: bool, color: slint::Color) {
    let app = ui.global::<AppState>();
    app.set_connected(connected);
    app.set_conn_label(if connected { "已连接" } else { "已断开" }.into());
    app.set_conn_color(color);
}

/// 同步各页面“已连接”开关（写操作按钮的启用条件）
fn set_pages_connected(ui: &AppWindow, on: bool) {
    ui.global::<ServerState>().set_connected(on);
    ui.global::<UsersState>().set_connected(on);
    ui.global::<SecurityState>().set_connected(on);
    ui.global::<FileLogsState>().set_connected(on);
    ui.global::<ServiceState>().set_connected(on);
}

/// 停止日志流：中止桥接任务；仍连接时向服务端退订
pub fn stop_log_stream(core: &SharedCore) {
    let mut c = core.lock().unwrap();
    stop_log_stream_locked(&mut c);
}

fn stop_log_stream_locked(c: &mut Core) {
    if let Some(handle) = c.log_abort.take() {
        handle.abort();
    }
    if let Some(conn) = c.ipc.conn().cloned() {
        let rt = c.rt.clone();
        rt.spawn(async move {
            let _ =
                ipc_service::request::<serde_json::Value>(conn, Command::UnsubscribeLogs).await;
        });
    }
}

/// 进入日志页且已连接时启动日志流桥接
///
/// 先订阅本地事件广播、再请求服务端 `SubscribeLogs`（先建接收端，
/// 保证服务端补推的历史不丢）；每条推送携带连接代数守卫，重连后的
/// 旧流静默退出；订阅失败/断流按断线收尾。
pub fn start_log_stream(weak: UiWeak, core: &SharedCore) {
    let (conn, stream_gen, rt) = {
        let c = core.lock().unwrap();
        if c.log_abort.is_some() || !c.ipc.is_connected() {
            return;
        }
        let Some(conn) = c.ipc.conn().cloned() else {
            return;
        };
        (conn, c.ipc.generation(), c.rt.clone())
    };
    let core = core.clone();
    let join = {
        let core = core.clone();
        rt.spawn(async move {
        let client = conn.0.clone();
        let mut rx = client.subscribe_events();
        if let Err(e) = client.request(Command::SubscribeLogs { tail_count: 200 }).await {
            let err = ipc_service::map_error(e);
            let w = weak.clone();
            let c2 = core.clone();
            let _ = w.upgrade_in_event_loop(move |ui| {
                c2.lock().unwrap().log_abort = None;
                if !relay(&ui, &c2, &err) {
                    ui.global::<LogsState>().set_error(err.message().into());
                }
            });
            return;
        }
        loop {
            match rx.recv().await {
                Ok(Event::Log { entry }) => {
                    if core.lock().unwrap().ipc.generation() != stream_gen {
                        return;
                    }
                    let w = weak.clone();
                    let c2 = core.clone();
                    let _ = w
                        .upgrade_in_event_loop(move |ui| logs::on_log_entry(&ui, &c2, &entry));
                }
                Ok(Event::FileOp { .. }) => {
                    // 审计实时流暂不在 GUI 展示（Web 端「文件日志」页消费）
                }
                Err(RecvError::Lagged(count)) => {
                    if core.lock().unwrap().ipc.generation() != stream_gen {
                        return;
                    }
                    let w = weak.clone();
                    let c2 = core.clone();
                    let _ = w
                        .upgrade_in_event_loop(move |ui| logs::on_log_lagged(&ui, &c2, count));
                }
                Err(RecvError::Closed) => break,
            }
        }
        // 订阅流结束：当代数未变（未被重连顶替）时按断线处理
        let _ = weak.upgrade_in_event_loop(move |ui| {
            if core.lock().unwrap().ipc.generation() == stream_gen {
                handle_disconnect(&ui, &core, "连接已断开".to_owned());
            }
        });
        })
    };
    core.lock().unwrap().log_abort = Some(join.abort_handle());
}
