# KCC API 参考

所有路径以 `web_base`（默认 `/kcc`）为前缀。除注明「公开」外，均需在请求头携带 `Authorization: Bearer <token>`。

## 0. 认证

### `POST /kcc/api/auth/login`（公开）
```bash
curl -s -X POST http://<host>:5005/kcc/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}'
```
返回：`{"token":"<jwt>","username":"admin"}`

### `GET /kcc/api/auth/me`
返回：`{"username":"admin","authenticated":true}`

### `GET /kcc/api/auth/init`（公开）
返回：`{"initialized":true,"user_count":1,"token_ttl_secs":28800}`

## 1. 巡检

### `GET /kcc/api/inspect/options`
返回可选巡检类型、格式、语言、级别。

### `POST /kcc/api/inspect` —— 触发巡检
请求体：
```json
{
  "types": ["all"],
  "namespace": null,
  "cluster_name": null,
  "format": "html",
  "lang": "zh",
  "level": "warning,critical",
  "node_inspector_namespace": null
}
```
`cluster_name` 可选：报告标题中显示的集群名称，等价于 CLI 的 `--cluster-name`；留空时自动从 kubeconfig 识别（识别不到则用 `default`）。
返回：`{"inspect_id":"<uuid4>"}`。任务异步执行。

### `GET /kcc/api/inspect/{id}` —— 查询状态/进度
返回：`{id,status,progress,current,total,score,report_id,types,format,lang,started_at,finished_at}`

### `GET /kcc/api/inspect/{id}/logs?cursor=N` —— 增量日志
返回：`{"logs":["..."],"cursor":N}`

### `GET /kcc/api/inspect/{id}/stream` —— SSE 实时日志
以 `data: ...` 事件流推送日志/状态/进度。

### `POST /kcc/api/inspect/{id}/cancel`
请求取消（协作式，模块间生效）。

### `GET /kcc/api/inspect/history`
返回：`{"runs":[{id,types,started_at,duration,status,score}]}`

## 2. 报告

### `GET /kcc/api/reports`
返回报告列表（报告 id 即 `ClusterReport.report_id`）。

### `GET /kcc/api/reports/{id}/download?format=html`
下载报告文件（支持已生成的 md/json/csv/html）。

### `DELETE /kcc/api/reports/{id}`
删除报告及其在索引中的记录。

## 3. 节点巡检状态

### `GET /kcc/api/nodes/inspector/status`
返回命名空间中各节点巡检 Pod 的可达性。

## 4. 节点巡检程序（DaemonSet 内部，端口 9090）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET  | `/kcc/api/health` | 存活探针，返回 node_name/version/ready |
| GET/POST | `/kcc/api/inspect` | 触发本节点巡检，返回 NodeInspectionResult JSON |
| GET  | `/kcc/api/inspect/status` | 本节点采集状态 |

示例：`curl -s http://<podIP>:9090/kcc/api/inspect`

## 5. 端到端时序

```
POST /kcc/api/inspect -> {inspect_id}
GET /kcc/api/inspect/{id}            (轮询 status/progress)
GET /kcc/api/inspect/{id}/stream     (SSE 日志，或 /logs 轮询)
完成后:
GET /kcc/api/reports                 -> report_id
GET /kcc/api/reports/{report_id}/download?format=html  -> 文件
```