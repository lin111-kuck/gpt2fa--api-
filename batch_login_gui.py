"""Chinese desktop UI for the existing batch account importer (Python + Tk)."""
import os
import queue
import threading
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

import batch_login as batch
import batch_gui_service as service

TITLE = '账号导入工作台'


class ImportApp:
    def __init__(self, root):
        self.root = root
        self.root.title(TITLE)
        self.root.geometry('1200x860')
        self.root.minsize(1040, 740)
        self.root.configure(bg='#eef2f7')
        self.events = queue.Queue()
        self.client = None
        self.groups = []
        self.busy = False
        self.closed = False
        self.close_when_done = False
        self.stop_event = threading.Event()
        self.result = None
        self.row_ids = {}
        self.finished_rows = {}
        self.total = 0
        self.connection_inputs = []
        self.task_inputs = []
        self.url = tk.StringVar(value=os.getenv('SUB2API_BASE_URL', ''))
        self.email = tk.StringVar(value=os.getenv('SUB2API_EMAIL', ''))
        self.password = tk.StringVar()
        self.show_password = tk.BooleanVar(value=False)
        self.direct = tk.BooleanVar(value=True)
        self.group_ids = tk.StringVar()
        self.group_choice = tk.StringVar()
        self.proxy_name = tk.StringVar()
        self.workers = tk.StringVar(value='3')
        self.mode = tk.StringVar(value='导入账号')
        self.engine = tk.StringVar(value='本地协议（自动取码）')
        self.max_ip = tk.StringVar(value='4')
        self.latency = tk.StringVar(value='300')
        self.resume_path = tk.StringVar()
        self.connection_status = tk.StringVar(value='未登录')
        self.task_status = tk.StringVar(value='请先登录后台，再粘贴账号并设置导入选项。')
        self.account_count = tk.StringVar(value='0 个账号')
        self.counts = tk.StringVar(value='总计 0   ·   已处理 0   ·   新增 0   ·   登录成功 0   ·   已存在 0   ·   失败 0')
        self.detail = tk.StringVar(value='选择一行查看详细结果。')
        self._style()
        self._build()
        self._refresh_controls()
        self.root.protocol('WM_DELETE_WINDOW', self.on_close)
        self.root.after(100, self._poll)

    def _style(self):
        self.root.option_add('*Font', ('Microsoft YaHei UI', 9))
        style = ttk.Style(self.root)
        style.theme_use('clam')
        style.configure('.', font=('Microsoft YaHei UI', 9), background='#eef2f7')
        style.configure('Card.TFrame', background='white')
        style.configure('Card.TLabel', background='white', foreground='#28374b')
        style.configure('Muted.TLabel', background='white', foreground='#6b7c93')
        style.configure('Card.TLabelframe', background='white', bordercolor='#dce4ee', relief='solid')
        style.configure('Card.TLabelframe.Label', background='#eef2f7', foreground='#334155', font=('Microsoft YaHei UI', 10, 'bold'))
        style.configure('TButton', padding=(10, 6))
        style.configure('Primary.TButton', background='#087f8c', foreground='white', padding=(16, 7))
        style.map('Primary.TButton', background=[('active', '#066875'), ('disabled', '#c7d1dc')])
        style.configure('Treeview', background='white', fieldbackground='white', rowheight=29, borderwidth=0)
        style.configure('Treeview.Heading', background='#e6edf5', foreground='#34465b', padding=7)
        style.map('Treeview', background=[('selected', '#d6eff1')], foreground=[('selected', '#163943')])
        style.configure('Horizontal.TProgressbar', background='#087f8c', troughcolor='#dfe7f0', borderwidth=0)

    def _build(self):
        header = tk.Frame(self.root, bg='#14253b', height=70)
        header.pack(fill='x')
        tk.Label(header, text=TITLE, fg='white', bg='#14253b', font=('Microsoft YaHei UI', 19, 'bold')).pack(anchor='w', padx=22, pady=(11, 0))
        tk.Label(header, text='批量导入  /  分组与代理绑定  /  实时任务进度', fg='#a9bfd5', bg='#14253b').pack(anchor='w', padx=23, pady=(0, 10))
        body = ttk.Frame(self.root, padding=(18, 10, 18, 10))
        body.pack(fill='both', expand=True)
        body.columnconfigure(0, weight=1)
        body.rowconfigure(2, weight=1)
        body.rowconfigure(4, weight=2)
        self._connection_panel(body)
        self._settings_panel(body)
        self._accounts_panel(body)
        actions = ttk.Frame(body)
        actions.grid(row=3, column=0, sticky='ew', pady=(8, 8))
        self.start_button = ttk.Button(actions, text='开始导入', style='Primary.TButton', command=self.start)
        self.start_button.pack(side='left')
        self.stop_button = ttk.Button(actions, text='停止后续任务', command=self.stop)
        self.stop_button.pack(side='left', padx=8)
        ttk.Label(actions, textvariable=self.counts).pack(side='left', padx=8)
        self.report_button = ttk.Button(actions, text='打开报告目录', command=self.open_reports)
        self.report_button.pack(side='right')
        self._results_panel(body)
        self.progress = ttk.Progressbar(body, maximum=100)
        self.progress.grid(row=5, column=0, sticky='ew', pady=(8, 5))
        ttk.Label(body, textvariable=self.task_status, foreground='#36516d', wraplength=1100).grid(row=6, column=0, sticky='w')

    def _entry(self, parent, variable, row, column, width=24, **kwargs):
        entry = ttk.Entry(parent, textvariable=variable, width=width, **kwargs)
        entry.grid(row=row, column=column, sticky='ew', padx=(4, 10), pady=4)
        return entry

    def _connection_panel(self, body):
        panel = ttk.LabelFrame(body, text='  1  管理员登录  ', style='Card.TLabelframe', padding=(12, 7))
        panel.grid(row=0, column=0, sticky='ew', pady=(0, 10))
        panel.columnconfigure(1, weight=2)
        panel.columnconfigure(3, weight=1)
        ttk.Label(panel, text='后台地址', style='Card.TLabel').grid(row=0, column=0, sticky='w')
        url_entry = self._entry(panel, self.url, 0, 1, 42)
        ttk.Label(panel, text='管理员邮箱', style='Card.TLabel').grid(row=0, column=2, sticky='w')
        email_entry = self._entry(panel, self.email, 0, 3, 30)
        ttk.Label(panel, textvariable=self.connection_status, foreground='#087f8c', style='Card.TLabel').grid(row=0, column=4, columnspan=3, sticky='w', padx=10)
        ttk.Label(panel, text='管理员密码', style='Card.TLabel').grid(row=1, column=0, sticky='w')
        self.password_entry = self._entry(panel, self.password, 1, 1, 32, show='•')
        self.password_toggle = ttk.Checkbutton(panel, text='显示密码', variable=self.show_password, command=self._toggle_password)
        self.password_toggle.grid(row=1, column=2, sticky='w')
        self.direct_check = ttk.Checkbutton(panel, text='直连后台', variable=self.direct)
        self.direct_check.grid(row=1, column=3, sticky='w', padx=4)
        self.login_button = ttk.Button(panel, text='登录', command=self.login, style='Primary.TButton')
        self.login_button.grid(row=1, column=4, padx=5)
        self.logout_button = ttk.Button(panel, text='退出登录', command=self.logout)
        self.logout_button.grid(row=1, column=5, padx=5)
        self.connection_inputs = [url_entry, email_entry, self.password_entry, self.direct_check, self.password_toggle]
        self.password_entry.bind('<Return>', lambda event: self.login())

    def _settings_panel(self, body):
        panel = ttk.LabelFrame(body, text='  2  导入选项  ', style='Card.TLabelframe', padding=(12, 7))
        panel.grid(row=1, column=0, sticky='ew', pady=(0, 10))
        panel.columnconfigure(1, weight=1)
        panel.columnconfigure(3, weight=1)
        ttk.Label(panel, text='分组 ID', style='Card.TLabel').grid(row=0, column=0, sticky='w')
        self.task_inputs.append(self._entry(panel, self.group_ids, 0, 1, 21))
        ttk.Label(panel, text='可用分组', style='Card.TLabel').grid(row=0, column=2, sticky='w')
        self.group_combo = ttk.Combobox(panel, textvariable=self.group_choice, width=31, state='readonly')
        self.group_combo.grid(row=0, column=3, sticky='ew', padx=5)
        self.add_group_button = ttk.Button(panel, text='加入分组', command=self.add_group)
        self.add_group_button.grid(row=0, column=4, padx=4)
        ttk.Label(panel, text='并发数', style='Card.TLabel').grid(row=0, column=5, padx=(12, 0))
        self.worker_spin = ttk.Spinbox(panel, textvariable=self.workers, from_=1, to=8, width=5)
        self.worker_spin.grid(row=0, column=6, padx=5)
        self.task_inputs.append(self.worker_spin)
        ttk.Label(panel, text='代理名称', style='Card.TLabel').grid(row=1, column=0, sticky='w')
        self.task_inputs.append(self._entry(panel, self.proxy_name, 1, 1, 21))
        ttk.Label(panel, text='运行模式', style='Card.TLabel').grid(row=1, column=2, sticky='w')
        self.mode_combo = ttk.Combobox(panel, textvariable=self.mode, values=list(service.MODES), state='readonly', width=16)
        self.mode_combo.grid(row=1, column=3, sticky='ew', padx=5)
        self.mode_combo.bind('<<ComboboxSelected>>', lambda event: self._refresh_controls())
        self.preview_button = ttk.Button(panel, text='预览匹配代理', command=self.preview_proxies)
        self.preview_button.grid(row=1, column=4, padx=4)
        ttk.Label(panel, text='IP 上限', style='Card.TLabel').grid(row=1, column=5, padx=(12, 0))
        self.task_inputs.append(self._entry(panel, self.max_ip, 1, 6, 5))
        advanced = ttk.Frame(panel, style='Card.TFrame')
        advanced.grid(row=2, column=0, columnspan=7, sticky='ew', pady=(3, 0))
        ttk.Label(advanced, text='登录方式', style='Muted.TLabel').pack(side='left')
        self.engine_combo = ttk.Combobox(advanced, textvariable=self.engine,
                                        values=list(service.ENGINES), state='readonly', width=23)
        self.engine_combo.pack(side='left', padx=(4, 12))
        ttk.Label(advanced, text='优先延迟 <', style='Muted.TLabel').pack(side='left')
        latency_entry = ttk.Entry(advanced, textvariable=self.latency, width=6)
        latency_entry.pack(side='left', padx=4)
        self.task_inputs.append(latency_entry)
        ttk.Label(advanced, text='ms · 代理名可留空；分组 ID 用逗号分隔。', style='Muted.TLabel').pack(side='left')
        self.resume_button = ttk.Button(advanced, text='选择恢复日志', command=self.choose_resume)
        self.resume_button.pack(side='right')
        self.resume_label = ttk.Label(advanced, text='全新任务', style='Muted.TLabel', width=20, anchor='e')
        self.resume_label.pack(side='right', padx=7)

    def _accounts_panel(self, body):
        panel = ttk.LabelFrame(body, text='  3  待处理账号  ', style='Card.TLabelframe', padding=(12, 6))
        panel.grid(row=2, column=0, sticky='nsew')
        panel.columnconfigure(0, weight=1)
        panel.rowconfigure(1, weight=1)
        toolbar = ttk.Frame(panel, style='Card.TFrame')
        toolbar.grid(row=0, column=0, sticky='ew', pady=(0, 5))
        ttk.Label(toolbar, text='邮箱----密码----2FA密钥----邮箱API；也支持 邮箱----邮箱API', style='Muted.TLabel').pack(side='left')
        ttk.Label(toolbar, textvariable=self.account_count, style='Card.TLabel').pack(side='right', padx=8)
        self.load_button = ttk.Button(toolbar, text='导入 TXT', command=self.load_accounts)
        self.load_button.pack(side='right', padx=3)
        self.format_button = ttk.Button(toolbar, text='检查格式', command=self.check_accounts)
        self.format_button.pack(side='right', padx=3)
        self.clear_button = ttk.Button(toolbar, text='清空', command=self.clear_accounts)
        self.clear_button.pack(side='right', padx=3)
        self.accounts = ScrolledText(panel, height=5, wrap='none', relief='solid', bd=1,
                                     font=('Consolas', 10), undo=False, bg='#f9fbfe', fg='#24374d')
        self.accounts.grid(row=1, column=0, sticky='nsew')
        self.accounts.bind('<<Modified>>', self._accounts_changed)

    def _results_panel(self, body):
        notebook = ttk.Notebook(body)
        notebook.grid(row=4, column=0, sticky='nsew')
        results = ttk.Frame(notebook)
        logs = ttk.Frame(notebook)
        notebook.add(results, text='  处理结果  ')
        notebook.add(logs, text='  实时日志  ')
        results.columnconfigure(0, weight=1)
        results.rowconfigure(0, weight=1)
        columns = ('email', 'status', 'id', 'proxy', 'ip', 'name', 'message')
        self.table = ttk.Treeview(results, columns=columns, show='headings', selectmode='browse')
        for key, title, width in zip(columns,
                ('账号邮箱', '状态', '账号 ID', '代理 ID', '出口 IP', '代理名称', '说明'),
                (250, 100, 65, 65, 130, 165, 240)):
            self.table.heading(key, text=title)
            self.table.column(key, width=width, minwidth=55, stretch=key == 'message')
        self.table.tag_configure('success', foreground='#087a62')
        self.table.tag_configure('error', foreground='#b54735')
        self.table.tag_configure('muted', foreground='#718095')
        self.table.grid(row=0, column=0, sticky='nsew')
        scroll = ttk.Scrollbar(results, orient='vertical', command=self.table.yview)
        scroll.grid(row=0, column=1, sticky='ns')
        horizontal = ttk.Scrollbar(results, orient='horizontal', command=self.table.xview)
        horizontal.grid(row=1, column=0, sticky='ew')
        self.table.configure(yscrollcommand=scroll.set, xscrollcommand=horizontal.set)
        self.table.bind('<<TreeviewSelect>>', self._select_result)
        ttk.Label(results, textvariable=self.detail, wraplength=1080, padding=6).grid(row=2, column=0, columnspan=2, sticky='ew')
        self.logs = ScrolledText(logs, state='disabled', wrap='word', height=8,
                                 font=('Microsoft YaHei UI', 9), bg='#f9fbfe', relief='flat')
        self.logs.pack(fill='both', expand=True)

    def _toggle_password(self):
        self.password_entry.configure(show='' if self.show_password.get() else '•')

    def _refresh_controls(self):
        connected = self.client is not None
        for widget in self.connection_inputs:
            widget.configure(state='disabled' if self.busy or connected else 'normal')
        self.login_button.configure(state='disabled' if self.busy or connected else 'normal')
        self.logout_button.configure(state='normal' if connected and not self.busy else 'disabled')
        for widget in self.task_inputs:
            widget.configure(state='disabled' if self.busy else 'normal')
        self.group_combo.configure(state='readonly' if connected and not self.busy else 'disabled')
        self.mode_combo.configure(state='disabled' if self.busy else 'readonly')
        self.engine_combo.configure(state='disabled' if self.busy else 'readonly')
        for widget in [self.add_group_button, self.preview_button]:
            widget.configure(state='normal' if connected and not self.busy else 'disabled')
        for widget in [self.load_button, self.format_button, self.clear_button, self.resume_button]:
            widget.configure(state='disabled' if self.busy else 'normal')
        self.accounts.configure(state='disabled' if self.busy else 'normal')
        self.start_button.configure(state='normal' if connected and not self.busy else 'disabled',
                                    text={'导入账号': '开始导入', '仅验证登录': '开始验证', '预检查': '开始预检查'}[self.mode.get()])
        self.stop_button.configure(state='normal' if self.busy and self.total else 'disabled')
        self.report_button.configure(state='normal' if self.result else 'disabled')

    def _launch(self, function, success):
        self.busy = True
        self._refresh_controls()
        def work():
            try:
                result = function()
                self.events.put((success, result))
            except Exception as exc:
                self.events.put(('error', str(exc) or type(exc).__name__))
        threading.Thread(target=work, daemon=False).start()

    def login(self):
        if self.busy or self.client:
            return
        url, email, password, direct = self.url.get(), self.email.get(), self.password.get(), self.direct.get()
        if not password:
            self.task_status.set('请填写管理员密码。')
            self.password_entry.focus_set()
            return
        self.total = 0
        self.connection_status.set('正在登录…')
        self.task_status.set('正在验证管理员身份并加载可用分组…')
        self._launch(lambda: service.authenticate(url, email, password, direct), 'authenticated')

    def logout(self):
        if self.busy:
            return
        self.client = None
        self.groups = []
        self.password.set('')
        self.group_combo.configure(values=[])
        self.group_choice.set('')
        self.connection_status.set('未登录')
        self.task_status.set('已退出登录。')
        self._refresh_controls()

    def add_group(self):
        if not self.group_choice.get():
            return
        try:
            ids = batch.parse_group_ids(self.group_ids.get()) if self.group_ids.get().strip() else []
            ids.append(int(self.group_choice.get().split(' · ', 1)[0]))
            self.group_ids.set(','.join(map(str, sorted(set(ids)))))
        except (batch.ApiError, ValueError) as exc:
            self.task_status.set(str(exc))

    def _settings(self):
        try:
            settings = service.Settings(self.group_ids.get(), self.proxy_name.get(), int(self.workers.get()),
                                        service.MODES[self.mode.get()], int(self.max_ip.get()),
                                        float(self.latency.get()), self.resume_path.get())
            settings.login_engine = service.ENGINES[self.engine.get()]
        except ValueError:
            raise batch.ApiError('并发数、IP 上限和延迟请填写有效数字。') from None
        service.options(settings)
        return settings

    def start(self):
        if self.busy or not self.client:
            return
        try:
            settings = self._settings()
            text = self.accounts.get('1.0', 'end-1c')
            batch.parse_entries(text)
        except batch.ApiError as exc:
            self.task_status.set(str(exc))
            return
        self.stop_event = threading.Event()
        self.total = 0
        self.result = None
        client = self.client
        self.task_status.set('正在准备任务…')
        self._launch(lambda: service.execute_batch(client, text, settings,
                       lambda event, data: self.events.put((event, data)), self.stop_event), 'completed')

    def stop(self):
        self.stop_event.set()
        self.stop_button.configure(state='disabled')
        self.task_status.set('正在停止后续任务；已提交的请求将完成处理并保存结果，请等待。')
        self._log('已请求停止后续任务。')

    def preview_proxies(self):
        if self.busy or not self.client:
            return
        try:
            settings = self._settings()
        except batch.ApiError as exc:
            self.task_status.set(str(exc))
            return
        self.total = 0
        client, keyword, limit = self.client, settings.proxy_name, settings.max_per_ip
        self.task_status.set('正在查询匹配代理的名称、状态和剩余容量…')
        self._launch(lambda: service.proxy_candidates(client, keyword, limit), 'proxies')

    def _show_proxies(self, rows):
        popup = tk.Toplevel(self.root)
        popup.title('匹配代理预览')
        popup.geometry('960x410')
        ttk.Label(popup, text=f'匹配且有容量的候选代理：{len(rows)} 个。导入时会再测试连通性及实际出口 IP。', padding=12).pack(anchor='w')
        columns = ('id', 'name', 'ip', 'country', 'count', 'latency')
        table = ttk.Treeview(popup, columns=columns, show='headings')
        for key, name, width in zip(columns, ('ID', '代理名称', '出口 IP', '地区', 'IP 账号数', '历史延迟 ms'), (60, 360, 140, 90, 90, 100)):
            table.heading(key, text=name)
            table.column(key, width=width, minwidth=50)
        scrollbar = ttk.Scrollbar(popup, orient='vertical', command=table.yview)
        scrollbar.pack(side='right', fill='y')
        table.configure(yscrollcommand=scrollbar.set)
        table.pack(fill='both', expand=True, padx=12, pady=(0, 12))
        for row in rows:
            table.insert('', 'end', values=(row['id'], row['name'], row['ip'], row['country'], row['account_count'], row['latency_ms']))

    def load_accounts(self):
        path = filedialog.askopenfilename(parent=self.root, title='选择账号文件', filetypes=[('账号文件', '*.txt'), ('所有文件', '*.*')])
        if not path:
            return
        try:
            content = Path(path).read_text(encoding='utf-8-sig')
            self.accounts.delete('1.0', 'end')
            self.accounts.insert('1.0', content)
            self.task_status.set(f'已载入：{Path(path).name}')
        except (OSError, UnicodeError):
            self.task_status.set('无法读取文件，请确认文件可访问且使用 UTF-8 编码。')

    def clear_accounts(self):
        self.accounts.delete('1.0', 'end')

    def check_accounts(self):
        try:
            entries = batch.parse_entries(self.accounts.get('1.0', 'end-1c'))
            self.task_status.set(f'格式检查通过：{len(entries)} 个账号；已校验邮箱、密钥和邮箱 API。')
        except batch.ApiError as exc:
            self.task_status.set(str(exc))

    def _accounts_changed(self, event=None):
        if self.accounts.edit_modified():
            count = sum(bool(line.strip()) and not line.strip().startswith('#')
                        for line in self.accounts.get('1.0', 'end-1c').splitlines())
            self.account_count.set(f'{count} 个账号')
            self.accounts.edit_modified(False)

    def choose_resume(self):
        path = filedialog.askopenfilename(parent=self.root, title='选择此前任务的 JSONL 日志',
                                          initialdir=str(service.ROOT / 'batch_results'), filetypes=[('任务日志', '*.jsonl')])
        if path:
            self.resume_path.set(path)
            self.resume_label.configure(text=Path(path).name)

    def open_reports(self):
        if self.result:
            path = Path(self.result['paths']['json']).parent
            if path.exists():
                os.startfile(str(path))

    def _log(self, message):
        self.logs.configure(state='normal')
        self.logs.insert('end', datetime.now().strftime('%H:%M:%S') + '  ' + message + '\n')
        self.logs.see('end')
        self.logs.configure(state='disabled')

    def _update_counts(self):
        rows = list(self.finished_rows.values())
        created = sum(r['status'] == 'created' for r in rows)
        verified = sum(bool(r.get('login_verified')) for r in rows)
        skipped = sum(r['status'].startswith('skipped_') for r in rows)
        failed = sum(r['status'] in ('failed', 'needs_review') for r in rows)
        self.counts.set(f'总计 {self.total}   ·   已处理 {len(rows)}   ·   新增 {created}   ·   登录成功 {verified}   ·   已存在 {skipped}   ·   失败 {failed}')
        self.progress['value'] = 100 * len(rows) / max(1, self.total)

    def _select_result(self, event=None):
        selection = self.table.selection()
        if selection:
            values = self.table.item(selection[0], 'values')
            self.detail.set(f'{values[0]}  |  {values[-1] or values[1]}')

    def _batch_event(self, data):
        event, email = data['event'], data.get('email')
        label = {
            'proxy_reserved': '已预留代理', 'login_submitted': '已提交登录',
            'login_verified': '登录身份核对成功', 'login_failed': '登录失败',
            'account_created': '已创建账号', 'account_complete': '代理、分组及登录凭据已保存',
            'login_cleanup_failed': '临时登录任务清理失败，请查看日志',
            'batch_error': '任务异常',
        }.get(event)
        if event == 'login_step':
            label = {'network_checking': '正在检测代理出口与地区',
                     'network_verifying': '正在复核登录出口', 'identity_verified': '凭证身份已核对，等待出口复核',
                     'authorize': '开始本地授权', 'email_submitted': '提交登录邮箱',
                     'password_submitted': '验证账号密码', 'totp_challenge': '验证 TOTP',
                     'email_otp_waiting': '等待邮箱 API 新验证码', 'email_otp_received': '已取到新邮件验证码',
                     'email_otp_resent': '已请求重发邮件验证码', 'email_otp_rejected': '验证码被拒绝，等待新码',
                     'workspace_selected': '选择工作区', 'token_exchange': '交换 OAuth 凭证',
                     'login_verified': '本地登录身份核对成功'}.get(data.get('step'), '正在本地登录')
        if event == 'login_network':
            label = '指纹已按出口匹配' if data.get('phase') == 'matched' else '登录出口复核通过'
        if label:
            suffix = f' · {data.get("exit_ip", "")}' if data.get('exit_ip') else ''
            if event == 'login_network':
                suffix += ' · ' + ' · '.join(str(data[k]) for k in
                                            ('country_code', 'timezone', 'language', 'browser') if data.get(k))
            if data.get('message'):
                suffix += ' · ' + data['message']
            self._log(f'{email + " · " if email else ""}{label}{suffix}')
        if email in self.row_ids and email not in self.finished_rows:
            values = list(self.table.item(self.row_ids[email], 'values'))
            if event in ('proxy_reserved', 'login_submitted', 'login_verified', 'account_created'):
                values[1] = {'proxy_reserved': '正在分配代理', 'login_submitted': '正在登录',
                             'login_verified': '登录成功，处理中', 'account_created': '正在保存设置'}[event]
                if data.get('proxy_id'):
                    values[3:6] = [data['proxy_id'], data.get('exit_ip', ''), data.get('proxy_name', '')]
                if data.get('account_id'):
                    values[2] = data['account_id']
                self.table.item(self.row_ids[email], values=values)

    def _handle(self, event, data):
        if event == 'authenticated':
            self.client, self.groups = data
            self.busy = False
            self.password.set('')
            self.show_password.set(False)
            self._toggle_password()
            self.connection_status.set('已登录 · ' + self.client.email)
            choices = [f'{g["id"]} · {g["name"]}' for g in self.groups]
            self.group_combo.configure(values=choices)
            self.group_choice.set(choices[0] if choices else '')
            if not self.group_ids.get().strip():
                defaults = [g['id'] for g in self.groups if g['name'] in batch.DEFAULT_GROUPS]
                self.group_ids.set(','.join(map(str, defaults)))
            self.task_status.set(f'登录成功，已加载 {len(self.groups)} 个可用分组。请填写账号及导入选项。')
            self._log('管理员登录成功，分组列表已加载。')
        elif event == 'started':
            self.table.delete(*self.table.get_children())
            self.row_ids.clear()
            self.finished_rows.clear()
            self.total = len(data['emails'])
            self.detail.set('任务运行中，可选择一行查看详情。')
            for email in data['emails']:
                self.row_ids[email] = self.table.insert('', 'end', values=(email, '等待处理', '', '', '', '', ''))
            self._update_counts()
            self.task_status.set('任务运行中。日志和结果会自动更新。')
            self._log(f'开始处理 {self.total} 个账号，模式：{self.mode.get()}。')
        elif event == 'event':
            self._batch_event(data)
        elif event == 'row':
            self.finished_rows[data['email']] = data
            status = data['status']
            tag = 'error' if status in ('failed', 'needs_review') else 'muted' if status.startswith('skipped') or status == 'stopped' else 'success'
            self.table.item(self.row_ids[data['email']], values=(data['email'], service.STATUS_LABELS.get(status, status),
                            data.get('account_id', ''), data.get('proxy_id', ''), data.get('exit_ip', ''),
                            data.get('proxy_name', ''), data.get('message', '')), tags=(tag,))
            self._log(f'{data["email"]} · {service.STATUS_LABELS.get(status, status)}')
            self._update_counts()
        elif event == 'completed':
            self.busy = False
            self.result = data
            summary = data['summary']
            for email, item in self.row_ids.items():
                if email not in self.finished_rows:
                    self.table.item(item, values=(email, '未处理', '', '', '', '', '任务已停止或异常，请查看日志。'), tags=('muted',))
            if data['error']:
                self.task_status.set('任务异常：' + data['error'] + '。已保存报告。')
            elif summary['failed'] or summary['unprocessed'] or summary['stopped']:
                self.task_status.set(f'任务结束：已处理 {summary["processed_count"]}/{summary["input_count"]}，失败 {summary["failed"]}，停止 {summary["stopped"]}。请查看结果及报告。')
            else:
                self.task_status.set(f'任务完成：新增 {summary["created"]}，登录成功 {summary["login_verified"]}，已存在 {summary["skipped"]}，预检查通过 {summary["planned"]}。报告已保存。')
            self._log(self.task_status.get())
        elif event == 'proxies':
            self.busy = False
            self.task_status.set(f'找到 {len(data)} 个匹配且有容量的候选代理。')
            self._show_proxies(data)
        elif event == 'error':
            self.busy = False
            if self.client is None:
                self.connection_status.set('登录未完成')
                self.password.set('')
            self.task_status.set('操作失败：' + data)
            self._log('操作失败：' + data)
        self._refresh_controls()
        if self.close_when_done and not self.busy:
            self.closed = True
            self.root.destroy()

    def _poll(self):
        try:
            for _ in range(150):
                event, data = self.events.get_nowait()
                self._handle(event, data)
                if self.closed:
                    return
        except queue.Empty:
            pass
        self.root.after(100, self._poll)

    def on_close(self):
        if self.busy:
            if messagebox.askyesno(TITLE, '任务仍在执行。是否停止后续任务，并在已提交请求完成后关闭？', parent=self.root):
                self.close_when_done = True
                self.stop()
            return
        self.password.set('')
        self.client = None
        self.closed = True
        self.root.destroy()


def main():
    root = tk.Tk()
    ImportApp(root)
    root.mainloop()


if __name__ == '__main__':
    main()
