//! 日志页：实时订阅 + 文本搜索 + 文件历史
//!
//! 实时条目由应用壳的日志流桥接任务推送（[`on_log_entry`]），写入
//! `Core::logs_live` 环形缓冲并按当前过滤条件追加到 UI 模型；级别过滤/
//! 搜索变更时从缓冲重建模型。文件历史经 `GetLogFiles` +
//! `GetLogFileContent` 切换到历史视图。级别着色与自动滚动在 Slint 侧
//! （`changed content-height` 驱动，仅实时视图且开关开启）。

use std::rc::Rc;

use fftp_ipc::protocol::{Command, LogEntry};
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};

use crate::app::{dispatch, relay, wire0, wire1, SharedCore, UiWeak};
use crate::ipc_service::{self, IpcError, LogEntries, LogFiles};
use crate::tabs::{file_options, row_index, ui_index, FileOption};
use crate::{AppWindow, LogRow, LogsState};

/// 内存中保留的最大实时日志条数
const MAX_ENTRIES: usize = 5000;

/// 文件历史一次加载的条数
const FILE_LOAD_COUNT: u32 = 500;

/// 日志级别过滤
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LevelFilter {
    /// 不过滤
    #[default]
    All,
    /// `ERROR`
    Error,
    /// `WARN`
    Warn,
    /// `INFO`
    Info,
    /// `DEBUG`
    Debug,
    /// `TRACE`
    Trace,
}

impl LevelFilter {
    /// 展示名
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            LevelFilter::All => "全部",
            LevelFilter::Error => "ERROR",
            LevelFilter::Warn => "WARN",
            LevelFilter::Info => "INFO",
            LevelFilter::Debug => "DEBUG",
            LevelFilter::Trace => "TRACE",
        }
    }

    /// 是否放行该级别（大小写不敏感）
    #[must_use]
    pub fn allows(self, level: &str) -> bool {
        match self {
            LevelFilter::All => true,
            filter => level.eq_ignore_ascii_case(filter.label()),
        }
    }
}

/// 从下拉索引还原级别过滤（与 `ui/logs.slint` 的 `ComboBox` 顺序一致）
#[must_use]
pub fn filter_from_idx(idx: i32) -> LevelFilter {
    match idx {
        1 => LevelFilter::Error,
        2 => LevelFilter::Warn,
        3 => LevelFilter::Info,
        4 => LevelFilter::Debug,
        5 => LevelFilter::Trace,
        _ => LevelFilter::All,
    }
}

/// 级别 + 文本搜索过滤（`query` 为已小写的搜索词）
fn matches(entry: &LogEntry, filter: LevelFilter, query: &str) -> bool {
    if !filter.allows(&entry.level) {
        return false;
    }
    if query.is_empty() {
        return true;
    }
    entry.message.to_lowercase().contains(query)
        || entry.source.to_lowercase().contains(query)
        || entry.username.to_lowercase().contains(query)
        || entry.action.to_lowercase().contains(query)
        || entry.client_ip.contains(query)
}

/// 回调接线
pub fn wire(weak: &UiWeak, core: &SharedCore) {
    let ui = weak.upgrade().unwrap();
    let state = ui.global::<LogsState>();
    state.on_clear(wire0(weak, core, on_clear));
    state.on_copy(wire0(weak, core, on_copy));
    state.on_export(wire0(weak, core, on_export));
    state.on_load_file(wire0(weak, core, load_file));
    state.on_back_live(wire0(weak, core, on_back_live));
    state.on_refresh_files(wire0(weak, core, refresh_files));
    state.on_select_file(wire1(weak, core, on_select_file));
    state.on_filter_changed(wire0(weak, core, rebuild));
    state.on_search_changed(wire0(weak, core, rebuild));
}

/// 实时日志条目：写入环形缓冲并按当前过滤条件追加到模型
pub fn on_log_entry(ui: &AppWindow, core: &SharedCore, entry: &LogEntry) {
    {
        let mut c = core.lock().unwrap();
        c.logs_live.push_back(entry.clone());
        while c.logs_live.len() > MAX_ENTRIES {
            c.logs_live.pop_front();
        }
    }
    push_row_if_visible(ui, entry);
}

/// 订阅落后：以合成条目提示丢弃数量
pub fn on_log_lagged(ui: &AppWindow, core: &SharedCore, count: u64) {
    on_log_entry(
        ui,
        core,
        &LogEntry {
            timestamp: String::new(),
            level: "WARN".to_owned(),
            source: "gui".to_owned(),
            message: format!("日志订阅落后，丢弃 {count} 条"),
            client_ip: String::new(),
            username: String::new(),
            action: String::new(),
        },
    );
}

/// 条目在当前过滤条件下可见时追加到模型
fn push_row_if_visible(ui: &AppWindow, entry: &LogEntry) {
    let state = ui.global::<LogsState>();
    if state.get_viewing_file() {
        return;
    }
    let filter = filter_from_idx(state.get_filter_idx());
    let query = state.get_search().trim().to_lowercase();
    if !matches(entry, filter, &query) {
        return;
    }
    let row = to_row(entry);
    let model = state.get_entries();
    if let Some(vec) = model.as_any().downcast_ref::<VecModel<LogRow>>() {
        vec.push(row);
        state.set_count(ui_index(vec.row_count()));
    } else {
        set_rows(ui, vec![row]);
    }
}

/// 按当前过滤条件从数据源重建模型（级别/搜索变更与视图切换时）
pub fn rebuild(ui: &AppWindow, core: &SharedCore) {
    let state = ui.global::<LogsState>();
    let filter = filter_from_idx(state.get_filter_idx());
    let query = state.get_search().trim().to_lowercase();
    let rows: Vec<LogRow> = {
        let c = core.lock().unwrap();
        let iter: Box<dyn Iterator<Item = &LogEntry>> = if state.get_viewing_file() {
            Box::new(c.logs_file_entries.iter())
        } else {
            Box::new(c.logs_live.iter())
        };
        iter.filter(|entry| matches(entry, filter, &query))
            .map(to_row)
            .collect()
    };
    set_rows(ui, rows);
}

/// 整体替换展示模型
fn set_rows(ui: &AppWindow, rows: Vec<LogRow>) {
    let state = ui.global::<LogsState>();
    state.set_entries(ModelRc::from(Rc::new(VecModel::from(rows))));
    state.set_count(ui_index(ui.global::<LogsState>().get_entries().row_count()));
}

/// 协议条目 → 展示行（级别归一为大写以匹配 UI 着色）
fn to_row(entry: &LogEntry) -> LogRow {
    LogRow {
        time: entry.timestamp.clone().into(),
        level: entry.level.to_uppercase().into(),
        source: entry.source.clone().into(),
        who: if entry.username.is_empty() && entry.client_ip.is_empty() {
            "".into()
        } else {
            format!("{}@{}", entry.username, entry.client_ip).into()
        },
        message: entry.message.clone().into(),
    }
}

/// 拉取日志文件列表（进入页面时刷新下拉）
pub fn refresh_files(ui: &AppWindow, core: &SharedCore) {
    let Some(conn) = core.lock().unwrap().ipc.conn().cloned() else {
        ui.global::<LogsState>()
            .set_error("未连接 fftpd，无法读取日志文件列表".into());
        return;
    };
    dispatch(
        ui.as_weak(),
        core,
        async move {
            ipc_service::request::<LogFiles>(conn, Command::GetLogFiles)
                .await
                .map(|r| file_options(&r.files))
        },
        on_files,
    );
}

/// `GetLogFiles` 响应：更新文件下拉并保持原选中
fn on_files(ui: &AppWindow, core: &SharedCore, result: Result<Vec<FileOption>, IpcError>) {
    let files = match result {
        Ok(files) => files,
        Err(e) => {
            ui.global::<LogsState>().set_error(e.message().into());
            relay(ui, core, &e);
            return;
        }
    };
    let names: Vec<SharedString> = files.iter().map(|f| f.name.clone().into()).collect();
    let selected_idx = {
        let mut c = core.lock().unwrap();
        if c.logs_selected.is_none() {
            c.logs_selected = files.first().cloned();
        }
        let idx = c
            .logs_selected
            .as_ref()
            .and_then(|sel| files.iter().position(|f| f.path == sel.path))
            .map_or(0, ui_index);
        c.logs_files = files;
        idx
    };
    let state = ui.global::<LogsState>();
    state.set_file_names(ModelRc::from(Rc::new(VecModel::from(names))));
    state.set_file_idx(selected_idx);
    state.set_error("".into());
}

/// 选择历史文件
fn on_select_file(ui: &AppWindow, core: &SharedCore, idx: i32) {
    let option = {
        let mut c = core.lock().unwrap();
        let option = c.logs_files.get(row_index(idx)).cloned();
        if option.is_some() {
            c.logs_selected.clone_from(&option);
        }
        option
    };
    if option.is_some() {
        load_file(ui, core);
    }
}

/// 加载历史文件内容
fn load_file(ui: &AppWindow, core: &SharedCore) {
    let Some((conn, path)) = ({
        let c = core.lock().unwrap();
        c.ipc
            .conn()
            .cloned()
            .zip(c.logs_selected.as_ref().map(|f| f.path.clone()))
    }) else {
        return;
    };
    dispatch(
        ui.as_weak(),
        core,
        async move {
            ipc_service::request::<LogEntries>(
                conn,
                Command::GetLogFileContent {
                    path,
                    count: FILE_LOAD_COUNT,
                },
            )
            .await
            .map(|r| r.entries)
        },
        on_file_entries,
    );
}

/// `GetLogFileContent` 响应：切换到历史视图
fn on_file_entries(ui: &AppWindow, core: &SharedCore, result: Result<Vec<LogEntry>, IpcError>) {
    match result {
        Ok(entries) => {
            core.lock().unwrap().logs_file_entries = entries;
            let state = ui.global::<LogsState>();
            state.set_viewing_file(true);
            state.set_error("".into());
            state.set_info("".into());
            rebuild(ui, core);
        }
        Err(e) => {
            ui.global::<LogsState>().set_error(e.message().into());
            relay(ui, core, &e);
        }
    }
}

/// 返回实时视图
fn on_back_live(ui: &AppWindow, core: &SharedCore) {
    ui.global::<LogsState>().set_viewing_file(false);
    rebuild(ui, core);
}

/// 清空实时日志
fn on_clear(ui: &AppWindow, core: &SharedCore) {
    core.lock().unwrap().logs_live.clear();
    rebuild(ui, core);
}

/// 复制当前显示内容到剪贴板
fn on_copy(ui: &AppWindow, core: &SharedCore) {
    let (content, count) = display_text(ui, core);
    let state = ui.global::<LogsState>();
    if content.is_empty() {
        state.set_info("没有可复制的日志".into());
        return;
    }
    // Slint 1.18 未公开剪贴板 API，直接用 winit 后端同款的 arboard；
    // 复制按钮运行在主线程（X11 要求剪贴板连接在主线程）
    let copied = arboard::Clipboard::new()
        .and_then(|mut cb| cb.set_text(content))
        .is_ok();
    state.set_info(if copied {
        format!("已复制 {count} 条日志到剪贴板").into()
    } else {
        "复制到剪贴板失败".into()
    });
}

/// 导出当前显示内容到文件
fn on_export(ui: &AppWindow, core: &SharedCore) {
    let (content, _) = display_text(ui, core);
    let state = ui.global::<LogsState>();
    if content.is_empty() {
        state.set_info("没有可导出的日志".into());
        return;
    }
    state.set_info("正在导出…".into());
    dispatch(ui.as_weak(), core, export_entries(content), on_exported);
}

/// 导出完成
fn on_exported(ui: &AppWindow, _core: &SharedCore, result: Result<String, String>) {
    let state = ui.global::<LogsState>();
    match result {
        Ok(path) => state.set_info(format!("日志已导出到：{path}").into()),
        Err(e) => state.set_error(e.into()),
    }
}

/// 当前显示内容的文本形式（复制/导出用），附带条数
fn display_text(ui: &AppWindow, core: &SharedCore) -> (String, usize) {
    let state = ui.global::<LogsState>();
    let filter = filter_from_idx(state.get_filter_idx());
    let query = state.get_search().trim().to_lowercase();
    let (lines, count) = {
        let c = core.lock().unwrap();
        let iter: Box<dyn Iterator<Item = &LogEntry>> = if state.get_viewing_file() {
            Box::new(c.logs_file_entries.iter())
        } else {
            Box::new(c.logs_live.iter())
        };
        let selected: Vec<&LogEntry> =
            iter.filter(|entry| matches(entry, filter, &query)).collect();
        let lines = selected
            .iter()
            .map(|entry| {
                format!(
                    "{}\t{}\t{}\t{}\t{}\t{}",
                    entry.timestamp,
                    entry.level,
                    entry.source,
                    entry.username,
                    entry.client_ip,
                    entry.message
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        (lines, selected.len())
    };
    (lines, count)
}

/// 导出日志到临时目录文件
async fn export_entries(content: String) -> Result<String, String> {
    let name = format!(
        "fftp-gui-logs-{}.txt",
        chrono::Utc::now().format("%Y%m%d-%H%M%S")
    );
    let path = std::env::temp_dir().join(name);
    tokio::fs::write(&path, content)
        .await
        .map_err(|e| format!("导出失败：{e}"))?;
    Ok(path.display().to_string())
}
