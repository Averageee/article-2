# AuthSystem — 基于 LWE 格密码与秘密共享的多因素认证系统

## 项目简介

本项目是一个研究原型，实现了一套结合以下密码学技术的多因素身份认证协议：

- **LWE（Learning With Errors）格密码**：用于密钥包装与传输，抵抗量子计算攻击
- **Shamir 秘密共享（CNF 访问结构）**：将主秘密分发到多台辅助设备，满足指定访问结构才能重构
- **模糊提取器（Fuzzy Extractor）**：支持生物特征（如指纹）认证
- **AES-256**：用于密码恢复材料的加密存储
- **双向认证**：服务器与客户端互相验证身份后协商会话密钥

**安全假设**：注册阶段信道完全安全；其他阶段信道均不可信，服务器和设备均为半可信（可被攻破）。

---

## 系统架构

```
┌─────────┐         ┌─────────────┐         ┌──────────┐
│  Client │◄───────►│   Server    │◄────────►│ Device i │
│(SmartCard)│       │  (Port 9000)│         │(Port 910i)│
└─────────┘         └─────────────┘         └──────────┘
```

| 组件 | 文件 | 角色 |
|------|------|------|
| Server | `server.cpp` | 认证服务器，存储用户注册信息，执行验证与密钥协商 |
| Device | `device.cpp` | 辅助设备，持有主秘密的份额 |
| Client | `client.cpp` | 用户端，模拟智能卡（SC）功能 |
| Common | `common.hpp` | 公共库：LWE、哈希、网络、AES、生物特征等工具 |

---

## 依赖环境

| 依赖 | 版本要求 | 安装命令（Ubuntu/Debian）|
|------|---------|------------------------|
| CMake | ≥ 3.15 | `sudo apt install cmake` |
| GCC / Clang | 支持 C++20 | `sudo apt install g++` |
| Boost.Asio | ≥ 1.74 | `sudo apt install libboost-all-dev` |
| OpenSSL | ≥ 1.1 | `sudo apt install libssl-dev` |
| nlohmann/json | 任意 | `sudo apt install nlohmann-json3-dev` |

---

## 编译

```bash
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j4
```

编译产物：`build/server`、`build/device`、`build/client`

---

## 运行

需要打开 **至少 5 个终端**（1 个 Server + N 个 Device + 1 个 Client）。

### 1. 启动 Server

```bash
cd build
./server
```

> Server 启动后等待控制台输入，**先不要输入**，待所有 Device 启动后再继续。

### 2. 启动 Device（每台一个终端）

```bash
# 终端 2
./device 1

# 终端 3
./device 2

# 终端 4
./device 3
```

每台 Device 会打印其监听端口（`9101`、`9102`、`9103`）。

### 3. 在 Server 控制台输入阶段一参数

```
[System] Enter device count N: 3
[System] Enter access structure (e.g. 1&2 or 1|2&3): 1&2&3
```

**访问结构语法**

| 表达式 | 含义 |
|--------|------|
| `1&2&3` | 需要设备 1、2、3 全部参与 |
| `1&2` | 只需设备 1 和 2 |
| `1\|2` | 设备 1 或设备 2 任一即可 |
| `1&2\|3` | （设备 1 且设备 2）或设备 3 |

分发完成后输出 `Phase 1 done. s destroyed.`，表示主秘密 s 已销毁，仅保留 H0(s)。

### 4. 启动 Client

```bash
# 终端 5
./client
```

Client 自动执行以下交互流程：

```
Phase 2  → 向 Server 注册（生成盐值 b、HPW、MID、生物特征处理、密钥恢复材料）
           ↓  按 Enter
Phase 3  → 从各 Device 收集份额，Lagrange 插值重构 s
Phase 4  → 智能卡本地 Ti* 验证 → 发送 LWE 加密认证请求
Phase 5  → 验证服务器 Ms1 → 发送 ACK → 双方输出相同会话密钥
           ↓  按 Enter（可选）
密码恢复  → 生物特征验证 → 安全问题回答 → AES 解密恢复 PW
```

### 5. 密码恢复演示

密码恢复阶段需要：

- **生物特征输入**：`fingerprint_user1`（原型固定值）
- **安全问题答案**（顺序不可错）：

| 题号 | 问题 | 答案 |
|------|------|------|
| Q1 | What is your pet's name? | `fluffy` |
| Q2 | What city were you born in? | `beijing` |
| Q3 | What is your mother's maiden name? | `chen` |

---

## 协议流程

### 阶段一：初始化分发

```
Server 生成随机主秘密 s ∈ [1, LWE_Q)
Server 按访问结构 AS 生成多项式，将份额 (x_i, f(x_i)) 发给各 Device
Server 存储 H0(s)，销毁 s 明文
```

### 阶段二：用户注册

```
Client → Server : uid, HPW=H0(pw|b), MID=H0(uid)
Server → Client : sigma1, d=a1·s_server+e, Ri=HPW⊕p, Ti, H0(s), N
Client 本地生成 : Gen(Bio)=(σ,θ), 密钥恢复多项式 f(x), δ_i, PWC=AES256(PW)
```

### 阶段三：份额收集

```
Client → Device_i : uid, HPW
Device_i → Client : y_masked = f(x_i) ⊕ HPW
Client 本地计算   : y = y_masked ⊕ HPW → Lagrange 插值重构 s
```

### 阶段四：身份验证

```
SmartCard 本地验证 Ti* == Ti（防暴力破解）
Client → Server : PID=MID⊕μ1, REP=(p⊕Auth)⊕H0(u1|μ1), u1, u2, c1_bar=Comp(d·s1'+Encode(s))
Server 验证      : 解密 s, 还原 MID, 验证 p（三重认证）
```

### 阶段五：密钥协商（双向认证）

```
Server → Client : Ms1=H1(ID||SERVER_ID||μ1||d2||p||μ2), d2, c2_bar
Client 验证 Ms1（服务器身份）
Client → Server : Mu1=H2(ID||SERVER_ID||μ1||d2||p||μ2)（ACK）
Server 验证 Mu1（客户端身份）
双方计算         : sk_u = H3(ID||SERVER_ID||μ1||d2||p||μ2)
```

### 阶段五（密码恢复）

```
本地操作（无需网络）：
用户输入生物特征 Bio* → Rep(Bio*, θ) == σ ?
用户回答安全问题 → 恢复 β_i → Lagrange 插值 → a0 → AES256.Dec(PWC) → PW
```

---

## 关键参数

| 参数 | 值 | 说明 |
|------|----|------|
| `LWE_N` | 64 | LWE 向量维度 |
| `LWE_Q` | 3329 | LWE 模数（与 Kyber 一致） |
| `LWE_NOISE_BOUND` | 0 | 噪声上界（原型设为 0 保证正确性） |
| `N0` | 10^9+7 | 多项式模数 |
| `N_SECURITY_Q` | 3 | 安全问题数量 |
| `SERVER_PORT` | 9000 | 服务器监听端口 |
| `DEVICE_BASE_PORT` | 9100 | 设备基础端口（设备 i 监听 9100+i） |

---

## 代码结构

```
code/
├── common.hpp      # 公共工具库（LWE、哈希、AES、网络、生物特征等）
├── server.cpp      # 服务器：注册、验证、密钥协商
├── device.cpp      # 辅助设备：存储并响应份额请求
├── client.cpp      # 客户端：完整认证流程 + 密码恢复
└── CMakeLists.txt  # 构建配置
```

---

## 安全说明与已知局限

| 项目 | 当前状态 | 生产环境建议 |
|------|---------|-------------|
| LWE 噪声 | `NOISE_BOUND=0`（无噪声，保证原型正确性） | 使用标准 Kyber 参数，配合 Encode/Decode 缩放 |
| 生物特征匹配 | 精确字符串匹配 | 接入真实模糊提取器（容许传感器误差） |
| 安全问题答案 | 硬编码在 `client.cpp` | 由用户在注册时交互输入 |
| 传输信道 | 无 TLS | 注册阶段应使用 TLS 加密信道 |
| 并发安全 | 基础 mutex | 生产环境需更细粒度锁或无锁结构 |
