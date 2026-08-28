# Loon AnyTLS Parser

一个面向 Loon 3.5.0(969)+ 的资源解析器插件：从当前订阅地址自动追加 `?t=clash` 获取 Clash/URI 内容，把其中的 `anytls://` URI 转换成 Loon 可识别的 `AnyTLS` 节点行，同时保留其他协议。

## 文件

- `Loon-AnyTLS-Parser.plugin`：Loon Parser Plugin 声明。
- `parser.js`：资源解析脚本。

## 使用

1. 提交并推送到 GitHub。
2. 在 Loon 中导入以下 Raw 地址作为 Parser：

   `https://raw.githubusercontent.com/moyucoding/loon-parser/main/Loon-AnyTLS-Parser.plugin`

3. 添加远程节点订阅时启用解析器。

脚本在 Loon 中读取 `$resource.link`，删除原有查询参数后追加 `?t=clash` 主动请求；订阅令牌不会写入仓库。Base64 订阅会先解码；非 Base64 内容直接逐行处理。只有格式正确的 `anytls://` 行会被转换，其他 URI 原样返回。Parser 脚本按照 Loon 接口直接通过 `$done(字符串)` 返回完整文本。

## 支持的 AnyTLS 参数

```text
anytls://密码@主机:端口?sni=example.com&insecure=1#节点名称
```

- `sni` 或 `peer` → `sni`
- `insecure=1` 或 `allowInsecure=1` → `skip-cert-verify=true`
- `udp=0` / `udp=false` → `udp=false`；其他显式 `udp` 值 → `udp=true`

## 说明

Loon 的资源解析器是全局单一解析器。若你已经使用 Sub-Store Parser，需要在两者之间选择一个；本插件的设计是让 Loon 继续解析除 AnyTLS 外的内容。

## 本地检查

```sh
node --check parser.js
node - <<'NODE'
const { transformSubscription } = require('./parser.js');
const input = 'anytls://secret@example.com:443?sni=edge.example.com&insecure=1#Tokyo\\nss://example';
console.log(transformSubscription(input));
NODE
```
