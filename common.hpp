#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <random>
#include <cmath>
#include <algorithm>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <boost/asio.hpp>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <openssl/evp.h>

using json = nlohmann::json;
using boost::asio::ip::tcp;

// --- 全局参数 ---
constexpr int    SERVER_PORT       = 9000;
constexpr int    DEVICE_BASE_PORT  = 9100;
// Kyber-1024 等效参数：n=256×k=4=1024 有效维度，q=3329，η=2
constexpr int    LWE_N             = 1024;
constexpr int    LWE_Q             = 3329;
constexpr int    LWE_NOISE_BOUND   = 2;             // CBD(η=2)，噪声范围 [-2, 2]
constexpr int    LWE_MSG_BITS      = 12;             // ⌈log₂(q)⌉ = 12，逐 bit 编码所需位数
constexpr long long N0             = 1000000007LL;   // Shamir/密钥恢复多项式模数
constexpr int    N_SECURITY_Q      = 3;              // 安全问题数量
const std::string SERVER_ID        = "SERVER_001";   // 服务器标识符

enum MsgType : uint32_t {
    Msg_Phase1_Share    = 1,
    Msg_Phase2_RegReq,  Msg_Phase2_RegResp,
    Msg_Phase3_FacReq,  Msg_Phase3_FacResp,
    Msg_Phase4_VerifyReq,
    Msg_Phase5_AuthResp,
    Msg_Phase5_AckReq   // 客户端向服务器发送 ACK（双向认证）
};

// --- 全局 RNG ---
inline std::mt19937_64 rng{std::random_device{}()};

// --- 日志工具 ---
class Logger {
public:
    static void print_phase(const std::string& title) {
        std::cout << "\n==================================================" << std::endl;
        std::cout << ">>> " << title << " <<<" << std::endl;
        std::cout << "--------------------------------------------------" << std::endl;
    }
    static void print_kv(const std::string& key, const std::string& val) {
        std::cout << " [*] " << std::left << std::setw(24) << key << ": " << val << std::endl;
    }
    static void print_kv(const std::string& key, long long val) {
        std::cout << " [*] " << std::left << std::setw(24) << key << ": " << val << std::endl;
    }
    static void print_kv(const std::string& key, double val) {
        std::cout << " [*] " << std::left << std::setw(24) << key << ": "
                  << std::fixed << std::setprecision(3) << val << std::endl;
    }
    // 打印 int 向量（显示前 max_show 个元素）
    static void print_vec(const std::string& key, const std::vector<int>& v,
                          size_t max_show = 6) {
        std::stringstream ss; ss << "[";
        size_t show = std::min(max_show, v.size());
        for (size_t i = 0; i < show; ++i) { ss << v[i]; if (i+1<show) ss << ", "; }
        if (v.size() > max_show) ss << ", ...";
        ss << "]  (len=" << v.size() << ")";
        print_kv(key, ss.str());
    }
    // 打印分阶段耗时（统一格式）
    static void print_time(double ms) {
        std::cout << " [Phase Time] " << std::fixed << std::setprecision(3)
                  << ms << " ms" << std::endl;
    }
    static void print_sep() {
        std::cout << "--------------------------------------------------" << std::endl;
    }
};

class Timer {
    using Clock = std::chrono::high_resolution_clock;
    Clock::time_point start;
public:
    Timer() { start = Clock::now(); }
    double ms() {
        return std::chrono::duration_cast<std::chrono::microseconds>(
            Clock::now() - start).count() / 1000.0;
    }
};

// ============================================================
// --- 哈希工具 ---
// ============================================================
inline std::string bytes_to_hex(const std::vector<uint8_t>& d) {
    std::stringstream ss; ss << std::hex << std::setfill('0');
    for (auto b : d) ss << std::setw(2) << (int)b;
    return ss.str();
}

inline std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
        bytes.push_back((uint8_t)std::stoi(hex.substr(i, 2), nullptr, 16));
    return bytes;
}

inline std::string vec_to_string(const std::vector<int>& v) {
    std::stringstream ss;
    for (auto x : v) ss << x << ",";
    return ss.str();
}

inline std::vector<uint8_t> H_Gen(const std::string& prefix, const std::string& s) {
    std::string d = prefix + s;
    std::vector<uint8_t> h(SHA256_DIGEST_LENGTH);
    SHA256((const uint8_t*)d.data(), d.size(), h.data());
    return h;
}
inline std::vector<uint8_t> H0(const std::string& s) { return H_Gen("H0", s); }
inline std::vector<uint8_t> H1(const std::string& s) { return H_Gen("H1", s); }
inline std::vector<uint8_t> H2(const std::string& s) { return H_Gen("H2", s); }
inline std::vector<uint8_t> H3(const std::string& s) { return H_Gen("H3", s); }

inline long long H_Int(const std::vector<uint8_t>& h) {
    long long r = 0;
    for (int i = 0; i < 8; ++i) r = (r << 8) | h[i];
    return r & 0x7FFFFFFFFFFFFFFF;
}

// ============================================================
// --- LWE 工具 ---
// ============================================================

// 生成 [-LWE_NOISE_BOUND, LWE_NOISE_BOUND] 范围的小噪声
inline int lwe_noise() {
    if (LWE_NOISE_BOUND == 0) return 0;
    std::uniform_int_distribution<int> dist(-LWE_NOISE_BOUND, LWE_NOISE_BOUND);
    return dist(rng);
}

// --- 逐 bit 编码/解码（Kyber 风格）---
// Encode: 1 bit → ⌊q/2⌋ 缩放
inline long long encode_bit(int bit) {
    return (long long)bit * ((LWE_Q + 1) / 2);   // 0 → 0,  1 → 1665
}
// Decode: 含噪值 → 1 bit（最近邻判定）
inline int decode_bit(long long val) {
    val = ((val % LWE_Q) + LWE_Q) % LWE_Q;
    return (val >= LWE_Q / 4 && val < 3 * LWE_Q / 4) ? 1 : 0;
}
// 整数 → bit 数组（LSB first）
inline std::vector<int> value_to_bits(long long s, int nbits = LWE_MSG_BITS) {
    std::vector<int> bits(nbits);
    for (int i = 0; i < nbits; i++) bits[i] = (int)((s >> i) & 1);
    return bits;
}
// bit 数组 → 整数
inline long long bits_to_value(const std::vector<int>& bits) {
    long long s = 0;
    for (int i = 0; i < (int)bits.size(); i++) s |= ((long long)bits[i] << i);
    return s;
}

// Comp / DeComp: 压缩/解压（原型中保持恒等，保证正确解密）
// 生产环境可改为 Kyber 风格的比特截断：round(c * 2^d / Q)
inline long long comp(long long c)       { return ((c % LWE_Q) + LWE_Q) % LWE_Q; }
inline long long decomp(long long c_bar) { return ((c_bar % LWE_Q) + LWE_Q) % LWE_Q; }

struct LWEVector {
    std::vector<int> data;
    LWEVector(int n = LWE_N) : data(n, 0) {}

    static LWEVector from_seed(long long seed) {
        LWEVector v;
        std::mt19937 gen((uint32_t)seed);
        for (int& x : v.data) x = gen() % LWE_Q;
        return v;
    }
    static LWEVector random() {
        return from_seed((long long)(rng() & 0x7FFFFFFFFFFFFFFF));
    }
    // 生成每个元素为小噪声的向量（用于 LWE 中的 e'）
    static LWEVector noise_vector() {
        LWEVector v;
        for (int& x : v.data) x = lwe_noise();
        return v;
    }

    int dot(const LWEVector& o) const {
        long long s = 0;
        for (int i = 0; i < LWE_N; ++i) s += (long long)data[i] * o.data[i];
        return (int)((s % LWE_Q + LWE_Q) % LWE_Q);
    }
    LWEVector scalar_mul(int s) const {
        LWEVector r;
        for (int i = 0; i < LWE_N; ++i)
            r.data[i] = (int)(((long long)data[i] * s % LWE_Q + LWE_Q) % LWE_Q);
        return r;
    }
    LWEVector add(const LWEVector& o) const {
        LWEVector r;
        for (int i = 0; i < LWE_N; ++i)
            r.data[i] = (int)(((long long)data[i] + o.data[i] + LWE_Q) % LWE_Q);
        return r;
    }
};

// ============================================================
// --- CNF 访问结构解析 ---
// ============================================================
class CNFParser {
public:
    static std::vector<std::vector<int>> parse(std::string p) {
        std::vector<std::vector<int>> g;
        std::stringstream ss(p); std::string seg;
        while (std::getline(ss, seg, '&')) {
            std::vector<int> cg;
            seg.erase(remove(seg.begin(), seg.end(), '('), seg.end());
            seg.erase(remove(seg.begin(), seg.end(), ')'), seg.end());
            std::stringstream ss2(seg); std::string d;
            while (std::getline(ss2, d, '|')) {
                try { cg.push_back(std::stoi(d)); } catch (...) {}
            }
            if (!cg.empty()) g.push_back(cg);
        }
        return g;
    }
};

// ============================================================
// --- 多项式秘密共享 ---
// ============================================================
struct Poly {
    std::vector<long long> c;
    long long M = N0;
    Poly(int d, long long s) {
        c.resize(d + 1); c[0] = s;
        std::uniform_int_distribution<long long> dist(0, M - 1);
        for (int i = 1; i <= d; ++i) c[i] = dist(rng);
    }
    long long eval(int x) {
        long long r = 0, p = 1;
        for (long long v : c) { r = (r + v * p) % M; p = (p * x) % M; }
        return r;
    }
};

// Lagrange 插值（修复：inv lambda 使用局部变量，不修改外部 M）
inline long long lagrange(const std::map<int, long long>& pts) {
    const long long M = N0;
    auto inv = [M](long long n) -> long long {
        long long mod = M, m0 = M, y = 0, x = 1;
        if (mod == 1) return 0LL;
        while (n > 1) {
            if (mod == 0) return 0LL;
            long long q = n / mod, t = mod;
            mod = n % mod; n = t; t = y; y = x - q * y; x = t;
        }
        if (x < 0) x += m0;
        return x;
    };
    long long s = 0;
    for (auto& i : pts) {
        long long num = 1, den = 1;
        for (auto& j : pts) {
            if (i.first == j.first) continue;
            num = (num % M * ((-j.first % M + M) % M)) % M;
            den = (den % M * (((long long)(i.first - j.first) % M + M) % M)) % M;
        }
        if (den == 0) continue;
        long long term = (i.second % M * num) % M;
        term = (term * inv(den)) % M;
        s = (s + term) % M;
    }
    return s;
}

// ============================================================
// --- 生物特征模糊提取器（简化模拟）---
// Gen(Bio) → (σ, θ)
// Rep(Bio*, θ) → σ 或空串（不匹配时）
// 真实场景应使用支持近似匹配的 Fuzzy Extractor
// ============================================================
inline std::pair<std::string, std::string> gen_bio(const std::string& bio) {
    return {bytes_to_hex(H0("bio_sigma|" + bio)),
            bytes_to_hex(H1("bio_theta|" + bio))};
}
inline std::string rep_bio(const std::string& bio_star, const std::string& theta) {
    if (bytes_to_hex(H1("bio_theta|" + bio_star)) != theta) return "";
    return bytes_to_hex(H0("bio_sigma|" + bio_star));
}

// ============================================================
// --- AES-256-ECB 加解密（用于密码恢复材料 PWC）---
// ============================================================
inline std::vector<uint8_t> aes256_key_from_scalar(long long a0) {
    auto h0 = H0(std::to_string(a0));
    auto h1 = H1(std::to_string(a0));
    std::vector<uint8_t> key(32);
    memcpy(key.data(),      h0.data(), 16);
    memcpy(key.data() + 16, h1.data(), 16);
    return key;
}
inline std::vector<uint8_t> aes256_encrypt(const std::string& plaintext, long long a0) {
    auto key = aes256_key_from_scalar(a0);
    // 将明文 zero-pad 到 16 字节（1 个 AES 分组）
    std::vector<uint8_t> padded(16, 0);
    size_t n = std::min(plaintext.size(), (size_t)16);
    memcpy(padded.data(), plaintext.data(), n);

    // 输出缓冲：Update 最多 16 字节，Final_ex 最多 16 字节（no-padding 时为 0）
    std::vector<uint8_t> ct(32, 0);
    int outlen1 = 0, outlen2 = 0;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key.data(), nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, 0);          // 禁用内置 padding，输入必须对齐分组
    EVP_EncryptUpdate(ctx, ct.data(), &outlen1, padded.data(), 16);
    EVP_EncryptFinal_ex(ctx, ct.data() + outlen1, &outlen2); // 刷出缓冲区
    EVP_CIPHER_CTX_free(ctx);
    ct.resize(outlen1 + outlen2);
    return ct;
}

inline std::string aes256_decrypt(const std::vector<uint8_t>& ciphertext, long long a0) {
    auto key = aes256_key_from_scalar(a0);
    // 输出缓冲：Update 最多 16 字节，Final_ex 最多 16 字节
    std::vector<uint8_t> pt(32, 0);
    int outlen1 = 0, outlen2 = 0;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key.data(), nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_DecryptUpdate(ctx, pt.data(), &outlen1, ciphertext.data(), (int)ciphertext.size());
    EVP_DecryptFinal_ex(ctx, pt.data() + outlen1, &outlen2); // 刷出缓冲区
    EVP_CIPHER_CTX_free(ctx);

    // 去除 zero-padding，还原原始明文
    int total = outlen1 + outlen2;
    int pw_len = total;
    for (int i = 0; i < total; ++i) {
        if (pt[i] == 0) { pw_len = i; break; }
    }
    return std::string(pt.begin(), pt.begin() + pw_len);
}

// ============================================================
// --- HPW / Ti 计算工具（客户端与服务器共享公式）---
// ============================================================
// HPW = H_Int(H0(pw + "|" + str(b)))
inline long long compute_HPW(const std::string& pw, long long b) {
    return H_Int(H0(pw + "|" + std::to_string(b)));
}
// MID = H_Int(H0(uid))
inline long long compute_MID(const std::string& uid) {
    return H_Int(H0(uid));
}
// T_i = H_Int(H0(str(MID ^ (HPW % N0))))，用于智能卡本地身份验证
inline long long compute_Ti(long long HPW, long long MID) {
    return H_Int(H0(std::to_string(MID ^ (HPW % N0))));
}

// ============================================================
// --- 网络通信工具 ---
// ============================================================
inline void send_packet(tcp::socket& s, uint32_t t, const json& j) {
    std::string b = j.dump();
    uint32_t h[2] = {htonl(t), htonl((uint32_t)b.size())};
    std::vector<uint8_t> buf(8 + b.size());
    memcpy(buf.data(), h, 8); memcpy(buf.data() + 8, b.data(), b.size());
    boost::asio::write(s, boost::asio::buffer(buf));
}
struct Packet { uint32_t type; json body; };
inline Packet read_packet(tcp::socket& s) {
    uint32_t h[2]; boost::asio::read(s, boost::asio::buffer(h, 8));
    uint32_t len = ntohl(h[1]);
    std::vector<char> b(len); boost::asio::read(s, boost::asio::buffer(b));
    return {ntohl(h[0]), json::parse(std::string(b.begin(), b.end()))};
}
