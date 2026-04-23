# Nginx 日志审计（Elasticsearch -> HTML）

## 快速开始

1) 安装依赖

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2) 配置

- 复制并修改 `config/audit.yaml`

3) 运行

```bash
python -m audit_nginx --config config/audit.yaml
```

运行后会在 `output.dir` 目录生成一份 `*.html` 审计报告。

## 你要“所有日志都让 AI 分析”

在 `config/audit.yaml` 里：

- `llm.per_event_enabled: true`
- `llm.per_event_batch_size`: 建议 10~50（越大越省请求，但单次更慢/更吃 token）
- 全量逐条结果会额外落盘到 `llm.per_event_jsonl_path`（jsonl），HTML 只展示前 200 条样本，避免报告过大打不开。

## 定时运行（示例）

### cron（每 6 小时跑一次）

编辑 crontab：

```bash
crontab -e
```

加入（注意把路径改成你的实际路径）：

```bash
0 */6 * * * cd /Users/jack/Desktop/siee && /Users/jack/Desktop/siee/.venv/bin/python -m audit_nginx --config config/audit.yaml >> ./logs/audit_cron.log 2>&1
```

### systemd timer（Linux 更推荐）

创建 `audit-nginx.service`：

```ini
[Unit]
Description=Nginx audit report generator

[Service]
Type=oneshot
WorkingDirectory=/opt/siee
ExecStart=/opt/siee/.venv/bin/python -m audit_nginx --config /opt/siee/config/audit.yaml
```

创建 `audit-nginx.timer`：

```ini
[Unit]
Description=Run nginx audit periodically

[Timer]
OnCalendar=*:0/360
Persistent=true

[Install]
WantedBy=timers.target
```

启用：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now audit-nginx.timer
systemctl list-timers --all | grep audit-nginx
```

