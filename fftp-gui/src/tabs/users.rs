//! 用户页：结构化用户管理（列表 + 新增/编辑/删除/改密对话框）
//!
//! 本地维护用户表并渲染列表；所有变更经 `GetUsers` → 应用 → `SaveUsers`
//! 以 `users.json` 原文整体提交（后端是唯一写入者）。原文的解析/序列化
//! 统一走 [`UserManager`]；新用户口令在 GUI 侧生成 Argon2id PHC 哈希
//! （参数与 `UserManager` 内部实现一致：`m=65536,t=3,p=4,len=32`）。

use std::collections::BTreeMap;

use argon2::password_hash::PasswordHasher;
use argon2::{Algorithm, Argon2, Version};
use chrono::Utc;
use fftp_common::users::{is_safe_username, Permissions, User, UserManager};
use fftp_ipc::protocol::Command;
use iced::widget::{button, checkbox, column, container, row, scrollable, text, text_input};
use iced::{Element, Length, Task};

use crate::app::Message;
use crate::ipc_service::{self, IpcConn, IpcError, IpcService, TextContent};
use crate::tabs::{error_line, form_row, info_line, relay_error, ERROR_COLOR, MUTED_COLOR};

/// 权限位（对应 [`Permissions`] 的 8 个开关）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Perm {
    /// 读取文件
    Read,
    /// 写入文件
    Write,
    /// 删除文件
    Delete,
    /// 列出目录
    List,
    /// 创建目录
    Mkdir,
    /// 删除目录
    Rmdir,
    /// 重命名
    Rename,
    /// 追加写入
    Append,
}

impl Perm {
    /// 全部权限位
    pub const ALL: [Self; 8] = [
        Perm::Read,
        Perm::Write,
        Perm::Delete,
        Perm::List,
        Perm::Mkdir,
        Perm::Rmdir,
        Perm::Rename,
        Perm::Append,
    ];

    /// 展示名
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Perm::Read => "读取",
            Perm::Write => "写入",
            Perm::Delete => "删除文件",
            Perm::List => "列出目录",
            Perm::Mkdir => "创建目录",
            Perm::Rmdir => "删除目录",
            Perm::Rename => "重命名",
            Perm::Append => "追加写入",
        }
    }

    /// 取权限位当前值
    #[must_use]
    pub fn get(self, perms: &Permissions) -> bool {
        match self {
            Perm::Read => perms.can_read,
            Perm::Write => perms.can_write,
            Perm::Delete => perms.can_delete,
            Perm::List => perms.can_list,
            Perm::Mkdir => perms.can_mkdir,
            Perm::Rmdir => perms.can_rmdir,
            Perm::Rename => perms.can_rename,
            Perm::Append => perms.can_append,
        }
    }

    /// 写权限位
    pub fn set(self, perms: &mut Permissions, on: bool) {
        match self {
            Perm::Read => perms.can_read = on,
            Perm::Write => perms.can_write = on,
            Perm::Delete => perms.can_delete = on,
            Perm::List => perms.can_list = on,
            Perm::Mkdir => perms.can_mkdir = on,
            Perm::Rmdir => perms.can_rmdir = on,
            Perm::Rename => perms.can_rename = on,
            Perm::Append => perms.can_append = on,
        }
    }
}

/// 新增/编辑用户表单
#[derive(Debug, Clone, Default)]
pub struct UserForm {
    /// 编辑目标用户名（`None` = 新增）
    pub editing: Option<String>,
    /// 用户名
    pub username: String,
    /// 口令（仅新增必填）
    pub password: String,
    /// 主目录
    pub home_dir: String,
    /// 权限
    pub permissions: Permissions,
    /// 管理员
    pub is_admin: bool,
    /// 启用
    pub enabled: bool,
    /// 配额文本（MB，空 = 不限）
    pub quota_mb: String,
    /// 限速文本（KB/s，空 = 不限）
    pub speed_limit_kbps: String,
    /// 表单错误
    pub error: Option<String>,
}

impl UserForm {
    /// 从既有用户构造编辑表单
    #[must_use]
    pub fn for_edit(user: &User) -> Self {
        Self {
            editing: Some(user.username.clone()),
            username: user.username.clone(),
            password: String::new(),
            home_dir: user.home_dir.clone(),
            permissions: user.permissions,
            is_admin: user.is_admin,
            enabled: user.enabled,
            quota_mb: user
                .permissions
                .quota_mb
                .map_or_else(String::new, |v| v.to_string()),
            speed_limit_kbps: user
                .permissions
                .speed_limit_kbps
                .map_or_else(String::new, |v| v.to_string()),
            error: None,
        }
    }

    /// 校验表单并构造 [`User`]
    ///
    /// `existing` 为编辑目标的既有记录（新增时为 `None`）。
    ///
    /// # Errors
    /// 用户名非法/重名、新增时口令为空、主目录为空或配额/限速数值非法时返回错误
    pub fn build(&self, existing: Option<&User>) -> Result<User, String> {
        if !is_safe_username(&self.username) {
            return Err(
                "用户名不合法：仅允许字母数字、下划线与连字符，长度 1~64，且以字母数字或下划线开头"
                    .to_owned(),
            );
        }
        if self.home_dir.trim().is_empty() {
            return Err("主目录不能为空".to_owned());
        }
        let mut permissions = self.permissions;
        permissions.quota_mb = parse_optional(&self.quota_mb, "配额（MB）")?;
        permissions.speed_limit_kbps = parse_optional(&self.speed_limit_kbps, "限速（KB/s）")?;

        if let Some(user) = existing {
            Ok(User {
                home_dir: self.home_dir.trim().to_owned(),
                permissions,
                is_admin: self.is_admin,
                enabled: self.enabled,
                ..user.clone()
            })
        } else {
            if self.password.is_empty() {
                return Err("新用户口令不能为空".to_owned());
            }
            Ok(User {
                username: self.username.trim().to_owned(),
                password_hash: hash_password(&self.password)?,
                home_dir: self.home_dir.trim().to_owned(),
                permissions,
                created_at: Utc::now(),
                last_login: None,
                enabled: self.enabled,
                is_admin: self.is_admin,
            })
        }
    }
}

/// 修改口令表单
#[derive(Debug, Clone, Default)]
pub struct PasswordForm {
    /// 用户名
    pub username: String,
    /// 新口令
    pub password: String,
    /// 确认口令
    pub confirm: String,
    /// 表单错误
    pub error: Option<String>,
}

/// 对话框状态
#[derive(Debug, Default)]
pub enum Dialog {
    /// 无对话框
    #[default]
    None,
    /// 新增/编辑用户
    User(Box<UserForm>),
    /// 修改口令
    Password(PasswordForm),
    /// 删除确认（附用户名）
    Delete(String),
}

/// 用户表单字段变更
#[derive(Debug, Clone)]
pub enum FormMsg {
    /// 用户名
    Username(String),
    /// 口令
    Password(String),
    /// 主目录
    HomeDir(String),
    /// 权限位
    Perm(Perm, bool),
    /// 配额（MB）
    Quota(String),
    /// 限速（KB/s）
    SpeedLimit(String),
    /// 管理员
    Admin(bool),
    /// 启用
    Enabled(bool),
}

/// 口令表单字段变更
#[derive(Debug, Clone)]
pub enum PasswordMsg {
    /// 新口令
    Password(String),
    /// 确认口令
    Confirm(String),
}

/// 用户页消息
#[derive(Debug, Clone)]
pub enum Msg {
    /// 载入 `users.json` 原文
    Content(String),
    /// 打开新增用户对话框
    New,
    /// 打开编辑对话框
    Edit(String),
    /// 打开删除确认
    Delete(String),
    /// 打开改密对话框
    ChangePassword(String),
    /// 关闭对话框
    Close,
    /// 用户表单字段
    Form(FormMsg),
    /// 口令表单字段
    Password(PasswordMsg),
    /// 创建主目录（`CreateUserDirectory`）
    CreateDir,
    /// 设置目录权限（`SetupDirectoryPermissions`）
    SetupDirPerms,
    /// 初始化用户目录（`EnsureUserDirectories`）
    EnsureDirs,
    /// 目录辅助操作完成（附成功提示）
    DirDone(Result<(), IpcError>, &'static str),
    /// 提交对话框（应用变更并保存）
    Submit,
    /// 确认删除
    ConfirmDelete,
    /// `SaveUsers` 响应（服务端返回的原文）
    Saved(Result<String, IpcError>),
}

/// 用户库变更（`GetUsers` → 应用 → `SaveUsers` 整体提交）
#[derive(Debug, Clone)]
enum UserOp {
    /// 新增/覆盖用户
    Upsert(User),
    /// 删除用户
    Delete(String),
    /// 修改口令（已哈希）
    SetPassword { username: String, hash: String },
}

/// 用户页状态
#[derive(Debug, Default)]
pub struct UsersTab {
    /// 本地用户表（按用户名排序展示）
    users: BTreeMap<String, User>,
    /// 当前对话框
    dialog: Dialog,
    /// 提交进行中
    busy: bool,
    error: Option<String>,
    info: Option<String>,
}

impl UsersTab {
    /// 更新页面状态；`ipc` 用于发起保存请求
    pub fn update(&mut self, msg: Msg, ipc: &IpcService) -> Task<Message> {
        match msg {
            Msg::Content(content) => {
                match parse_users(&content) {
                    Ok(users) => {
                        self.users = users;
                        self.error = None;
                    }
                    Err(e) => self.error = Some(e),
                }
                self.info = None;
                Task::none()
            }
            Msg::New => {
                self.dialog = Dialog::User(Box::new(UserForm {
                    enabled: true,
                    ..UserForm::default()
                }));
                Task::none()
            }
            Msg::Edit(username) => {
                if let Some(user) = self.users.get(&username) {
                    self.dialog = Dialog::User(Box::new(UserForm::for_edit(user)));
                } else {
                    self.error = Some(format!("用户不存在：{username}"));
                }
                Task::none()
            }
            Msg::Delete(username) => {
                self.dialog = Dialog::Delete(username);
                Task::none()
            }
            Msg::ChangePassword(username) => {
                self.dialog = Dialog::Password(PasswordForm {
                    username,
                    ..PasswordForm::default()
                });
                Task::none()
            }
            Msg::Close => {
                self.dialog = Dialog::None;
                Task::none()
            }
            Msg::Form(m) => {
                if let Dialog::User(form) = &mut self.dialog {
                    apply_form(form, m);
                }
                Task::none()
            }
            Msg::Password(m) => {
                if let Dialog::Password(form) = &mut self.dialog {
                    match m {
                        PasswordMsg::Password(v) => form.password = v,
                        PasswordMsg::Confirm(v) => form.confirm = v,
                    }
                }
                Task::none()
            }
            Msg::CreateDir => self.dir_op(ipc, DirOp::Create),
            Msg::SetupDirPerms => self.dir_op(ipc, DirOp::Perms),
            Msg::EnsureDirs => self.dir_op(ipc, DirOp::Ensure),
            Msg::DirDone(result, ok_text) => self.on_dir_done(result, ok_text),
            Msg::Submit => self.submit(ipc),
            Msg::ConfirmDelete => {
                let Dialog::Delete(username) = &self.dialog else {
                    return Task::none();
                };
                let op = UserOp::Delete(username.clone());
                self.dispatch(ipc, op)
            }
            Msg::Saved(result) => self.on_saved(result),
        }
    }

    /// 目录辅助操作响应
    fn on_dir_done(&mut self, result: Result<(), IpcError>, ok_text: &'static str) -> Task<Message> {
        self.busy = false;
        match result {
            Ok(()) => {
                self.error = None;
                self.info = Some(ok_text.to_owned());
                Task::none()
            }
            Err(e) => {
                self.error = Some(e.message().to_owned());
                relay_error(&e)
            }
        }
    }

    /// `SaveUsers` 响应：刷新本地用户表
    fn on_saved(&mut self, result: Result<String, IpcError>) -> Task<Message> {
        self.busy = false;
        match result {
            Ok(content) => {
                match parse_users(&content) {
                    Ok(users) => self.users = users,
                    Err(e) => self.error = Some(e),
                }
                self.dialog = Dialog::None;
                self.error = None;
                self.info = Some("用户库已保存".to_owned());
                Task::none()
            }
            Err(e) => {
                self.error = Some(e.message().to_owned());
                relay_error(&e)
            }
        }
    }

    /// 校验对话框并生成变更操作
    fn submit(&mut self, ipc: &IpcService) -> Task<Message> {
        let op = match &mut self.dialog {
            Dialog::User(form) => {
                let existing = form.editing.as_ref().and_then(|name| self.users.get(name));
                match form.build(existing) {
                    Ok(user) => {
                        if form.editing.is_none() && self.users.contains_key(&user.username) {
                            form.error = Some(format!("用户已存在：{}", user.username));
                            return Task::none();
                        }
                        UserOp::Upsert(user)
                    }
                    Err(e) => {
                        form.error = Some(e);
                        return Task::none();
                    }
                }
            }
            Dialog::Password(form) => {
                if form.password.is_empty() {
                    form.error = Some("新口令不能为空".to_owned());
                    return Task::none();
                }
                if form.password != form.confirm {
                    form.error = Some("两次输入的口令不一致".to_owned());
                    return Task::none();
                }
                match hash_password(&form.password) {
                    Ok(hash) => UserOp::SetPassword {
                        username: form.username.clone(),
                        hash,
                    },
                    Err(e) => {
                        form.error = Some(e);
                        return Task::none();
                    }
                }
            }
            _ => return Task::none(),
        };
        self.dispatch(ipc, op)
    }

    /// 提交变更（经 `GetUsers` → 应用 → `SaveUsers`）
    fn dispatch(&mut self, ipc: &IpcService, op: UserOp) -> Task<Message> {
        let Some(conn) = ipc.conn().cloned() else {
            self.error = Some("未连接 fftpd，无法保存".to_owned());
            return Task::none();
        };
        self.busy = true;
        self.error = None;
        self.info = None;
        Task::perform(apply_op(conn, op), |r| Message::Users(Msg::Saved(r)))
    }

    /// 目录辅助操作
    fn dir_op(&mut self, ipc: &IpcService, op: DirOp) -> Task<Message> {
        let Some(conn) = ipc.conn().cloned() else {
            self.error = Some("未连接 fftpd，无法操作目录".to_owned());
            return Task::none();
        };
        let path = match &self.dialog {
            Dialog::User(form) => form.home_dir.trim().to_owned(),
            _ => String::new(),
        };
        if matches!(op, DirOp::Create | DirOp::Perms) && path.is_empty() {
            self.error = Some("请先填写主目录".to_owned());
            return Task::none();
        }
        self.busy = true;
        self.error = None;
        self.info = None;
        let cmd = match op {
            DirOp::Create => Command::CreateUserDirectory { path },
            DirOp::Perms => Command::SetupDirectoryPermissions { path },
            DirOp::Ensure => Command::EnsureUserDirectories,
        };
        let ok_text = match op {
            DirOp::Create => "目录已创建",
            DirOp::Perms => "目录权限已设置",
            DirOp::Ensure => "用户目录已初始化",
        };
        Task::perform(
            async move { ipc_service::request_ok(conn, cmd).await },
            move |r| Message::Users(Msg::DirDone(r, ok_text)),
        )
    }

    /// 渲染页面
    #[must_use]
    pub fn view(&self, connected: bool) -> Element<'_, Message> {
        let mut toolbar = row![
            text("用户管理").size(22),
            button(text("新增用户")).on_press_maybe(
                (!self.busy && matches!(self.dialog, Dialog::None)).then_some(Message::Users(Msg::New))
            ),
        ]
        .spacing(10);
        if let Some(info) = &self.info {
            toolbar = toolbar.push(info_line(info));
        }

        let mut page = column![toolbar].spacing(10).width(Length::Fill).height(Length::Fill);
        if let Some(error) = &self.error {
            page = page.push(error_line(error));
        }
        page = page.push(match &self.dialog {
            Dialog::None => text("口令以 Argon2id 哈希存储；变更经“保存”整体提交到 users.json。")
                .size(12)
                .color(MUTED_COLOR)
                .into(),
            Dialog::User(form) => self.user_dialog(form, connected),
            Dialog::Password(form) => password_dialog(form, connected, self.busy),
            Dialog::Delete(username) => delete_dialog(username, connected, self.busy),
        });
        page = page.push(self.user_list());
        page.into()
    }

    /// 用户列表
    fn user_list(&self) -> Element<'_, Message> {
        let header = row![
            text("用户名").size(13).width(Length::Fixed(130.0)),
            text("状态").size(13).width(Length::Fixed(70.0)),
            text("角色").size(13).width(Length::Fixed(70.0)),
            text("主目录").size(13).width(Length::Fill),
            text("配额").size(13).width(Length::Fixed(100.0)),
            text("限速").size(13).width(Length::Fixed(100.0)),
            text("操作").size(13).width(Length::Fixed(210.0)),
        ]
        .spacing(10);

        let rows = column(self.users.values().map(|user| user_row(user, self.busy))).spacing(4);
        container(
            column![
                header,
                scrollable(rows).height(Length::Fill),
            ]
            .spacing(6),
        )
        .padding(12)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(container::rounded_box)
        .into()
    }

    /// 新增/编辑对话框
    fn user_dialog(&self, form: &UserForm, connected: bool) -> Element<'_, Message> {
        let title = if form.editing.is_some() {
            "编辑用户"
        } else {
            "新增用户"
        };
        let mut fields = column![
            text(title).size(18),
            form_row(
                "用户名",
                text_input("字母数字/_/-", &form.username)
                    .on_input_maybe(
                        form.editing.is_none()
                            .then_some(|v| Message::Users(Msg::Form(FormMsg::Username(v))))
                    )
                    .width(Length::Fixed(280.0)),
            ),
            form_row(
                "主目录",
                text_input("/srv/ftp/user", &form.home_dir)
                    .on_input(|v| Message::Users(Msg::Form(FormMsg::HomeDir(v))))
                    .width(Length::Fixed(360.0)),
            ),
            suggested_row(&form.username),
            row![
                button(text("创建目录")).on_press_maybe(
                    (connected && !self.busy).then_some(Message::Users(Msg::CreateDir))
                ),
                button(text("设置目录权限")).on_press_maybe(
                    (connected && !self.busy).then_some(Message::Users(Msg::SetupDirPerms))
                ),
                button(text("初始化用户目录")).on_press_maybe(
                    (connected && !self.busy).then_some(Message::Users(Msg::EnsureDirs))
                ),
            ]
            .spacing(8),
        ]
        .spacing(8);

        if form.editing.is_none() {
            fields = fields.push(form_row(
                "口令",
                text_input("新用户口令", &form.password)
                    .on_input(|v| Message::Users(Msg::Form(FormMsg::Password(v))))
                    .secure(true)
                    .width(Length::Fixed(280.0)),
            ));
        }

        let perms = column(Perm::ALL.map(|perm| {
            Element::from(checkbox(perm.label(), perm.get(&form.permissions)).on_toggle(
                move |on| Message::Users(Msg::Form(FormMsg::Perm(perm, on))),
            ))
        }))
        .spacing(4);

        fields = fields.push(row![
            column![
                checkbox("启用", form.enabled)
                    .on_toggle(|v| Message::Users(Msg::Form(FormMsg::Enabled(v)))),
                checkbox("管理员", form.is_admin)
                    .on_toggle(|v| Message::Users(Msg::Form(FormMsg::Admin(v)))),
            ]
            .spacing(6),
            column![
                form_row(
                    "配额（MB）",
                    text_input("不限", &form.quota_mb)
                        .on_input(|v| Message::Users(Msg::Form(FormMsg::Quota(v))))
                        .width(Length::Fixed(120.0)),
                ),
                form_row(
                    "限速（KB/s）",
                    text_input("不限", &form.speed_limit_kbps)
                        .on_input(|v| Message::Users(Msg::Form(FormMsg::SpeedLimit(v))))
                        .width(Length::Fixed(120.0)),
                ),
            ]
            .spacing(6),
            column![text("权限").size(13), perms].spacing(6),
        ].spacing(24).align_y(iced::Alignment::Start));

        if let Some(error) = &form.error {
            fields = fields.push(error_line(error));
        }
        fields = fields.push(
            row![
                button(text("保存")).on_press_maybe(
                    (connected && !self.busy).then_some(Message::Users(Msg::Submit))
                ),
                button(text("取消")).on_press_maybe((!self.busy).then_some(Message::Users(Msg::Close))),
            ]
            .spacing(8),
        );

        container(fields.spacing(8))
            .padding(16)
            .width(Length::Fill)
            .style(container::rounded_box)
            .into()
    }
}

/// 目录辅助操作
#[derive(Debug, Clone, Copy)]
enum DirOp {
    /// 创建目录
    Create,
    /// 设置目录权限
    Perms,
    /// 初始化用户目录
    Ensure,
}

/// 用户列表行
fn user_row(user: &User, busy: bool) -> Element<'_, Message> {
    let username = user.username.clone();
    row![
        text(user.username.clone()).size(13).width(Length::Fixed(130.0)),
        text(if user.enabled { "启用" } else { "禁用" })
            .size(13)
            .color(if user.enabled {
                crate::tabs::INFO_COLOR
            } else {
                ERROR_COLOR
            })
            .width(Length::Fixed(70.0)),
        text(if user.is_admin { "管理员" } else { "普通" })
            .size(13)
            .width(Length::Fixed(70.0)),
        text(user.home_dir.clone()).size(13).width(Length::Fill),
        text(limit_text(user.permissions.quota_mb, "MB"))
            .size(13)
            .width(Length::Fixed(100.0)),
        text(limit_text(user.permissions.speed_limit_kbps, "KB/s"))
            .size(13)
            .width(Length::Fixed(100.0)),
        row![
            button(text("编辑")).on_press_maybe(
                (!busy).then_some(Message::Users(Msg::Edit(username.clone())))
            ),
            button(text("改密")).on_press_maybe(
                (!busy).then_some(Message::Users(Msg::ChangePassword(username.clone())))
            ),
            button(text("删除")).on_press_maybe((!busy).then_some(Message::Users(Msg::Delete(username)))),
        ]
        .spacing(4)
        .width(Length::Fixed(210.0)),
    ]
    .spacing(10)
    .into()
}

/// 改密对话框
fn password_dialog(form: &PasswordForm, connected: bool, busy: bool) -> Element<'_, Message> {
    let mut fields = column![
        text(format!("修改口令：{}", form.username)).size(18),
        form_row(
            "新口令",
            text_input("新口令", &form.password)
                .on_input(|v| Message::Users(Msg::Password(PasswordMsg::Password(v))))
                .secure(true)
                .width(Length::Fixed(280.0)),
        ),
        form_row(
            "确认口令",
            text_input("再输入一次", &form.confirm)
                .on_input(|v| Message::Users(Msg::Password(PasswordMsg::Confirm(v))))
                .secure(true)
                .width(Length::Fixed(280.0)),
        ),
    ]
    .spacing(8);
    if let Some(error) = &form.error {
        fields = fields.push(error_line(error));
    }
    fields = fields.push(
        row![
            button(text("保存")).on_press_maybe((connected && !busy).then_some(Message::Users(Msg::Submit))),
            button(text("取消")).on_press_maybe((!busy).then_some(Message::Users(Msg::Close))),
        ]
        .spacing(8),
    );
    container(fields)
        .padding(16)
        .width(Length::Fill)
        .style(container::rounded_box)
        .into()
}

/// 删除确认对话框
fn delete_dialog(username: &str, connected: bool, busy: bool) -> Element<'_, Message> {
    container(
        column![
            text(format!("确认删除用户 “{username}”？")).size(18),
            text("删除后需保存才会写入 users.json，此操作不可撤销。").size(13),
            row![
                button(text("确认删除")).on_press_maybe(
                    (connected && !busy).then_some(Message::Users(Msg::ConfirmDelete))
                ),
                button(text("取消")).on_press_maybe((!busy).then_some(Message::Users(Msg::Close))),
            ]
            .spacing(8),
        ]
        .spacing(10),
    )
    .padding(16)
    .width(Length::Fill)
    .style(container::rounded_box)
    .into()
}

/// 建议主目录行（点击填入表单）
fn suggested_row(username: &str) -> Element<'static, Message> {
    let buttons = suggested_dirs(username).into_iter().map(|dir| {
        Element::from(button(text(shorten(&dir, 24))).on_press(Message::Users(Msg::Form(
            FormMsg::HomeDir(dir),
        ))))
    });
    row![
        text("建议目录").size(13).width(Length::Fixed(150.0)),
        row(buttons).spacing(6),
    ]
    .spacing(8)
    .into()
}

/// 建议的主目录候选（本地计算，参考旧版 Linux GUI 的 `suggested_dirs`）
fn suggested_dirs(username: &str) -> Vec<String> {
    let mut dirs = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        let base = std::path::PathBuf::from(&home);
        dirs.push(home);
        for sub in ["Desktop", "Documents", "Downloads"] {
            let path = base.join(sub);
            if path.is_dir() {
                dirs.push(path.to_string_lossy().into_owned());
            }
        }
        dirs.push(base.join(format!("ftp-{username}")).to_string_lossy().into_owned());
    }
    dirs.push(format!("/srv/ftp/{username}"));
    dirs.push(format!("/var/ftp/{username}"));
    dirs
}

/// 路径缩写展示
fn shorten(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let tail: String = s.chars().rev().take(max.saturating_sub(1)).collect();
        format!("…{}", tail.chars().rev().collect::<String>())
    }
}

/// 配额/限速展示文本
fn limit_text(value: Option<u64>, unit: &str) -> String {
    match value {
        Some(v) => format!("{v} {unit}"),
        None => "不限".to_owned(),
    }
}

/// 表单字段应用
fn apply_form(form: &mut UserForm, msg: FormMsg) {
    match msg {
        FormMsg::Username(v) => form.username = v,
        FormMsg::Password(v) => form.password = v,
        FormMsg::HomeDir(v) => form.home_dir = v,
        FormMsg::Perm(perm, on) => perm.set(&mut form.permissions, on),
        FormMsg::Quota(v) => form.quota_mb = v,
        FormMsg::SpeedLimit(v) => form.speed_limit_kbps = v,
        FormMsg::Admin(v) => form.is_admin = v,
        FormMsg::Enabled(v) => form.enabled = v,
    }
    form.error = None;
}

/// 解析可选数值（空 = 不限）
fn parse_optional(value: &str, label: &str) -> Result<Option<u64>, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    trimmed
        .parse::<u64>()
        .map(Some)
        .map_err(|_| format!("{label}不是合法数字：{trimmed}"))
}

/// 生成 Argon2id PHC 口令哈希
///
/// 参数与 [`UserManager`] 内部实现一致（`m=65536,t=3,p=4,len=32`）；
/// 后者未暴露公开哈希接口，故 GUI 侧按同参数生成。
fn hash_password(password: &str) -> Result<String, String> {
    let params = argon2::Params::new(65536, 3, 4, Some(32))
        .map_err(|e| format!("口令哈希参数非法：{e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|e| format!("口令哈希失败：{e}"))
}

/// 解析 `users.json` 原文为本地用户表
fn parse_users(content: &str) -> Result<BTreeMap<String, User>, String> {
    let manager: UserManager =
        serde_json::from_str(content).map_err(|e| format!("用户库解析失败：{e}"))?;
    Ok(manager
        .get_users()
        .iter()
        .map(|(name, user)| (name.clone(), user.clone()))
        .collect())
}

/// 把 [`User`] 写回 [`UserManager`]（内部映射字段私有，经 JSON 往返完成）
fn upsert_user(manager: &UserManager, user: &User) -> Result<UserManager, IpcError> {
    let mut value = serde_json::to_value(manager)
        .map_err(|e| IpcError::Request(format!("用户库序列化失败：{e}")))?;
    let users = value
        .get_mut("users")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| IpcError::Request("用户库结构不符合预期".to_owned()))?;
    let serialized =
        serde_json::to_value(user).map_err(|e| IpcError::Request(format!("用户序列化失败：{e}")))?;
    users.insert(user.username.clone(), serialized);
    serde_json::from_value(value).map_err(|e| IpcError::Request(format!("用户库解析失败：{e}")))
}

/// 应用变更：`GetUsers` → 应用 → `SaveUsers` 整体提交
async fn apply_op(conn: IpcConn, op: UserOp) -> Result<String, IpcError> {
    let current = ipc_service::request::<TextContent>(conn.clone(), Command::GetUsers).await?;
    let mut manager: UserManager = serde_json::from_str(&current.content)
        .map_err(|e| IpcError::Request(format!("用户库解析失败：{e}")))?;
    manager = match op {
        UserOp::Upsert(user) => upsert_user(&manager, &user)?,
        UserOp::Delete(username) => {
            manager
                .remove_user(&username)
                .map_err(|e| IpcError::Request(format!("{e:#}")))?;
            manager
        }
        UserOp::SetPassword { username, hash } => {
            let mut user = manager
                .get_user(&username)
                .cloned()
                .ok_or_else(|| IpcError::Request(format!("用户不存在：{username}")))?;
            user.password_hash = hash;
            upsert_user(&manager, &user)?
        }
    };
    let content = serde_json::to_string_pretty(&manager)
        .map_err(|e| IpcError::Request(format!("用户库序列化失败：{e}")))?;
    ipc_service::request::<TextContent>(conn, Command::SaveUsers { content })
        .await
        .map(|c| c.content)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_user() -> User {
        User {
            username: "alice".to_owned(),
            password_hash: hash_password("s3cret").unwrap(),
            home_dir: "/srv/ftp/alice".to_owned(),
            permissions: Permissions::full(),
            created_at: Utc::now(),
            last_login: None,
            enabled: true,
            is_admin: false,
        }
    }

    #[test]
    fn hash_password_produces_current_policy_phc() {
        let hash = hash_password("s3cret").unwrap();
        assert!(hash.starts_with("$argon2id$v=19$m=65536,t=3,p=4$"));
    }

    #[test]
    fn users_content_roundtrip_via_user_manager() {
        let mut users = BTreeMap::new();
        users.insert("alice".to_owned(), sample_user());

        // 本地表 → UserManager → users.json 原文 → 本地表
        let value = serde_json::json!({ "users": users });
        let manager: UserManager = serde_json::from_value(value).unwrap();
        let content = serde_json::to_string_pretty(&manager).unwrap();
        let parsed = parse_users(&content).unwrap();

        assert_eq!(parsed.len(), 1);
        let alice = parsed.get("alice").unwrap();
        assert_eq!(alice.home_dir, "/srv/ftp/alice");
        assert!(alice.permissions.can_read);
        assert_eq!(alice.permissions.quota_mb, None);
    }

    #[test]
    fn upsert_user_replaces_and_preserves_others() {
        let manager: UserManager =
            serde_json::from_value(serde_json::json!({ "users": { "alice": sample_user() } }))
                .unwrap();
        let mut bob = sample_user();
        bob.username = "bob".to_owned();
        bob.home_dir = "/srv/ftp/bob".to_owned();
        let merged = upsert_user(&manager, &bob).unwrap();
        assert_eq!(merged.get_users().len(), 2);
        assert_eq!(merged.get_user("alice").unwrap().home_dir, "/srv/ftp/alice");
        assert_eq!(merged.get_user("bob").unwrap().home_dir, "/srv/ftp/bob");
    }

    #[test]
    fn build_user_validates_and_keeps_identity() {
        let mut form = UserForm::for_edit(&sample_user());
        form.home_dir = "  ".to_owned();
        assert!(form.build(Some(&sample_user())).is_err());

        let mut form = UserForm::for_edit(&sample_user());
        form.home_dir = "/data/alice".to_owned();
        form.quota_mb = "100".to_owned();
        form.speed_limit_kbps = "512".to_owned();
        let edited = form.build(Some(&sample_user())).unwrap();
        assert_eq!(edited.username, "alice");
        assert_eq!(edited.home_dir, "/data/alice");
        assert_eq!(edited.permissions.quota_mb, Some(100));
        assert_eq!(edited.permissions.speed_limit_kbps, Some(512));

        // 新增：口令必填、用户名必须安全
        let form = UserForm {
            username: "bad name".to_owned(),
            home_dir: "/srv/ftp/x".to_owned(),
            ..UserForm::default()
        };
        assert!(form.build(None).is_err());

        let mut form = UserForm {
            username: "bob".to_owned(),
            home_dir: "/srv/ftp/x".to_owned(),
            // 与新增对话框（Msg::New）一致：默认启用
            enabled: true,
            ..UserForm::default()
        };
        assert!(form.build(None).is_err(), "新用户口令为空应报错");

        form.password = "pw".to_owned();
        let user = form.build(None).unwrap();
        assert_eq!(user.username, "bob");
        assert!(user.enabled);
    }

    #[test]
    fn parse_optional_blank_means_unlimited() {
        assert_eq!(parse_optional("  ", "配额").unwrap(), None);
        assert_eq!(parse_optional("10", "配额").unwrap(), Some(10));
        assert!(parse_optional("x", "配额").is_err());
    }
}
