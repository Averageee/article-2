# UCMFAWPR — 后量子安全的用户自主多因素认证系统演示

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

Client 启动后输入凭据和安全问题答案，然后选择运行模式：

```
 [Mode] 0 = 完整交互流程 (含密码恢复输入)
        1 = Benchmark (N 轮自动运行, 输出平均时间)
```

**Mode 0（完整流程）**：

```
Phase 2  → 注册阶段（Client ↔ Server）
Phase 3  → 登录阶段（Ti 验证 + 份额收集 + 构建认证请求）
Phase 4  → 验证 + 密钥协商（发送 → 服务器验证 → 双方密钥交换）
           ↓  按 Enter
Phase 5  → 密码恢复（用户输入 ID、生物特征、安全问题 → 恢复密码）
```

**Mode 1（Benchmark）**：输入轮数 N 和模拟单向网络延迟（ms），Phase 2→5 自动执行 N 轮，最后输出各阶段平均耗时。建议延迟设为 20-50ms 以反映真实广域网环境。

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

### 阶段三：登录阶段

```
1. 客户端选择满足访问结构的设备集合
2. Device_i → Client : y_masked = sub_s_i ⊕ HPW（子句子秘密掩码传输）
3. Client 本地计算   : sub_s = y_masked ⊕ HPW → 加法重构 s = Σ sub_s_i (mod q)
4. SmartCard 本地验证 Ti* == Ti（防暴力破解）
5. 构建 LWE 加密认证请求：u1, u2, c̄1[12]=逐bit(d·s1'+e_c+encode_bit(s_j)), PID, REP, Mi
```

### 阶段四：验证 + 密钥协商（双向认证）

```
Client → Server : PID, REP, Mi, u1, u2, c̄1, σ2
Server 验证      : LWE 解密恢复 s → 验证 H0(s) / ID / p / Mi（三重认证）
Server → Client : Ms1=H1(IDi||IDs||μ1||d2||p||μ2), d2, c̄2
Client 验证      : LWE 解密 c̄2 恢复 v2→μ2, 验证 Ms1（服务器身份）
Client → Server : Mu1=H2(IDi||IDs||μ1||d2||p||μ2)（ACK）
Server 验证 Mu1（客户端身份）
双方计算         : sk_u = H3(IDi||IDs||μ1||d2||p||μ2)
```

### 阶段五：密码恢复

```
本地操作（无需网络）：
1. 用户输入 ID* → 智能卡校验 ID* == ID_stored
2. 用户输入 Bio* → Rep(Bio*, θ) == σ ?
3. 用户回答安全问题 Ans_i → β_i = δ_i ⊕ H1(H2(Ans_i)||(H2(ID) mod n0))
4. Lagrange 插值 → a0 = f(0)
5. PW = AES256.Dec(a0, PWC)
```

---

## 公共参数

以下所有参数定义于 `common.hpp`，编译时为全局常量。

### 密码学参数

| 参数 | 符号 | 具体值 | 说明 |
|------|------|--------|------|
| LWE 向量维度 | n | `LWE_N = 1024` | 等效于 Kyber-1024（n=256 × k=4），NIST Level 5 安全等级（≈AES-256） |
| LWE 模数 | q | `LWE_Q = 3329` | 所有 LWE 运算的有限域模数，取自 NIST ML-KEM (Kyber) 标准参数 |
| LWE 噪声参数 | η | `LWE_NOISE_BOUND = 2` | 噪声/秘密采样范围 [-η, η]，等同 Kyber-1024 的 CBD(η=2) |
| 逐 bit 编码位数 | — | `LWE_MSG_BITS = 12` | ⌈log₂(q)⌉ = 12，将消息逐 bit 编码为 12 个 LWE 密文 |
| 多项式模数 | n₀ | `N0 = 1000000007` (10⁹+7) | Shamir 秘密共享与密码恢复多项式的有限域模数（大素数） |
| 安全问题数量 | N | `N_SECURITY_Q = 3` | 密码恢复所需的安全问题数，即恢复多项式 f(x) 的阶数 = N-1 = 2 |
| 服务器标识符 | ID_s | `SERVER_ID = "SERVER_001"` | 密钥协商阶段用于构造 Ms1/Mu1/sk_u 的服务器身份字符串 |

### 哈希函数族

| 函数 | 定义 | 用途 |
|------|------|------|
| H₀(·) | SHA-256("H0" \|\| input) | HPW、MID、Ti、μ₁=H₀(s)、p_stored、认证因子 p |
| H₁(·) | SHA-256("H1" \|\| input) | Ms1 = H₁(ID_i \|\| ID_s \|\| μ₁ \|\| d₂ \|\| p \|\| μ₂)，密码恢复 δᵢ 掩码 |
| H₂(·) | SHA-256("H2" \|\| input) | Mu1 = H₂(…)（ACK），密码恢复 ID 绑定 |
| H₃(·) | SHA-256("H3" \|\| input) | 会话密钥 sk_u = H₃(ID_i \|\| ID_s \|\| μ₁ \|\| d₂ \|\| p \|\| μ₂) |
| H_Int(·) | 取 SHA-256 输出前 8 字节转 63-bit 正整数 | 将哈希映射为可做算术运算的整数 |

### LWE 编码函数（逐 bit 编码，Kyber 风格）

| 函数 | 实现 | 说明 |
|------|------|------|
| encode_bit(b) | b × ⌊q/2⌋ = b × 1665 | 将 1 bit 编码到 [0, q) 区间，0→0，1→1665 |
| decode_bit(v) | v ∈ [q/4, 3q/4) → 1，否则 → 0 | 最近邻判定，容许噪声 < q/4 ≈ 832 |
| value_to_bits(s) | s 的 12-bit 二进制展开（LSB first） | 将消息拆分为 12 个 bit |
| bits_to_value(bits) | 12-bit 重组为整数 | 从解码的 12 bit 恢复原始消息 |
| Comp(c) / DeComp(c̄) | c mod q（恒等） | 密文压缩/解压（原型保持恒等） |

### AES 参数

| 参数 | 值 | 说明 |
|------|-----|------|
| 算法 | AES-256-ECB | 用于加密密码恢复材料 PWC = AES_Enc(a₀, PW) |
| 密钥生成 | key = H₀(a₀)[0:16] \|\| H₁(a₀)[0:16] | 从多项式秘密值 a₀ 派生 32 字节密钥 |
| 分组大小 | 16 字节 | 密码明文 zero-pad 到 16 字节 |

### 网络参数

| 参数 | 值 | 说明 |
|------|-----|------|
| 服务器端口 | `SERVER_PORT = 9000` | 认证服务器 TCP 监听端口 |
| 设备基础端口 | `DEVICE_BASE_PORT = 9100` | 设备 i 监听端口 = 9100 + i |
| 传输协议 | TCP（Boost.Asio） | 自定义二进制协议：4 字节消息类型 + 4 字节长度 + JSON body |
| 模拟单向延迟 | `SIMULATED_DELAY_MS`（运行时输入） | 每次 send/read 前休眠，模拟真实广域网延迟。典型值：20-50ms |

### 生物特征参数

| 参数 | 值 | 说明 |
|------|-----|------|
| Gen(Bio) | σ = H₀("bio_sigma\|" + Bio), θ = H₁("bio_theta\|" + Bio) | 模糊提取器生成函数（简化为精确哈希） |
| Rep(Bio*, θ) | 验证 H₁("bio_theta\|" + Bio*) == θ → 输出 σ | 模糊提取器恢复函数（精确匹配，非真实容错） |

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
| LWE 参数 | Kyber-1024 等效（n=1024, q=3329, η=2），逐 bit 编码保证正确解密 | 已对齐 NIST ML-KEM Level 5 标准参数 |
| 生物特征匹配 | 精确字符串匹配 | 接入真实模糊提取器（容许传感器误差） |
| 安全问题答案 | 硬编码在 `client.cpp` | 由用户在注册时交互输入 |
| 传输信道 | 无 TLS | 注册阶段应使用 TLS 加密信道 |
| 并发安全 | 基础 mutex | 生产环境需更细粒度锁或无锁结构 |
