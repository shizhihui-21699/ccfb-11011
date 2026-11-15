# ZTNA Access Proxy (demo)

把内部系统从 VPN 迁到零信任的访问代理原型，TypeScript 实现。

## 架构

```
设备(客户端证书) ──mTLS──> 代理 :8443 ──> 身份认证(本地 IdP 模拟)
                              │
                              ├─> 姿态服务 :8300 (模拟 MDM/EDR 上报)
                              ├─> 策略引擎 (config/policies.json, 按应用配置)
                              ├─> 审计日志 (audit.log + 内存)
                              ├─> 内部应用 :9001 finance / :9002 wiki (模拟)
                              └─> 管理台 :8200 (设备/会话/策略/审计)
```

- **设备身份**：自签 CA 签发客户端证书，设备 ID 放在证书 CN 和 SAN URI(`urn:device:<id>`)。代理 `rejectUnauthorized: true`，无证书连 TLS 握手都过不了。
- **用户身份**：本地 IdP 模拟（scrypt 口令校验），登录后签发 HMAC 签名 Cookie 会话，会话绑定设备 ID（换设备 Cookie 即失效）。
- **访问策略**：按应用配置 `allowUsers` + 姿态要求（最低系统版本、磁盘加密、EDR 在线、姿态上报新鲜度），见 `config/policies.json`。
- **持续评估**：每 10 秒对活跃会话重新求值，姿态不达标立即收回会话（实测 <5s，要求 1 分钟内）。
- **审计**：登录、每次放行/拒绝、会话收回、姿态上报全部记录到 `audit.log` 并在管理台展示。

## 运行

```bash
npm install
npm run setup     # 生成 CA、服务器证书、设备证书 (certs/)
npm start         # 启动全部组件
```

管理台： http://127.0.0.1:8200

## 模拟设备上报姿态

```bash
npx tsx scripts/simulate-device.ts laptop-01 15.2 true true    # 健康
npx tsx scripts/simulate-device.ts laptop-01 15.2 true false   # EDR 掉线 -> 会话被收回
```

## curl 走一遍

```bash
C="--cacert certs/ca.crt.pem --cert certs/device-laptop-01.crt.pem --key certs/device-laptop-01.key.pem"
curl -sk $C -c /tmp/c.txt -X POST -d "username=alice&password=alice-pass" https://localhost:8443/login
curl -sk $C -b /tmp/c.txt https://localhost:8443/app/finance/
```

浏览器访问需把 `certs/device-laptop-01.crt.pem` + `.key.pem` 打包成 PKCS#12 导入：
`openssl pkcs12 -export -out laptop-01.p12 -inkey certs/device-laptop-01.key.pem -in certs/device-laptop-01.crt.pem`

## 演示用户

alice / bob / carol，密码均为 `<名字>-pass`。finance 仅 alice 可访问，wiki 三人皆可。

## 策略写法

```json
{
  "apps": {
    "finance": {
      "upstream": "http://127.0.0.1:9001",
      "allowUsers": ["alice"],
      "require": {
        "minOsVersion": "15.0",
        "diskEncrypted": true,
        "edrOnline": true,
        "maxPostureAgeSec": 120
      }
    }
  }
}
```

## 代码结构

| 文件 | 职责 |
|---|---|
| `src/ca.ts` | 自签 CA、签发服务器/设备证书、从对端证书提取设备 ID |
| `src/proxy.ts` | mTLS 终结、登录、按应用策略求值、反向代理、持续评估收回会话 |
| `src/policy.ts` | 策略类型与求值（版本比较、加密、EDR、新鲜度） |
| `src/posture.ts` | 模拟姿态服务（设备上报 / 查询） |
| `src/sessions.ts` | 会话存储，HMAC 签名 Cookie |
| `src/idp.ts` | 本地用户认证（模拟 IdP） |
| `src/audit.ts` | 审计日志（JSONL + 内存） |
| `src/admin.ts` | 管理台页面与 API |
| `src/backends.ts` | 模拟内部应用 |
| `scripts/setup-certs.ts` | 生成整套证书 |
| `scripts/simulate-device.ts` | 模拟设备姿态上报 |
