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
#include <boost/asio.hpp>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>

using json = nlohmann::json;
using boost::asio::ip::tcp;

// --- 全局参数 ---
constexpr int SERVER_PORT = 9000;
constexpr int DEVICE_BASE_PORT = 9100;
constexpr int LWE_N = 64;   
constexpr int LWE_Q = 3329;  

enum MsgType : uint32_t {
    Msg_Phase1_Share = 1, 
    Msg_Phase2_RegReq, Msg_Phase2_RegResp,   
    Msg_Phase3_FacReq, Msg_Phase3_FacResp,   
    Msg_Phase4_VerifyReq, Msg_Phase5_AuthResp   
};

// --- 日志工具 ---
class Logger {
public:
    static void print_phase(const std::string& title) {
        std::cout << "\n==================================================" << std::endl;
        std::cout << ">>> " << title << " <<<" << std::endl;
        std::cout << "--------------------------------------------------" << std::endl;
    }
    static void print_kv(const std::string& key, const std::string& val) {
        std::cout << " [*] " << std::left << std::setw(20) << key << ": " << val << std::endl;
    }
    static void print_kv(const std::string& key, long long val) {
        std::cout << " [*] " << std::left << std::setw(20) << key << ": " << val << std::endl;
    }
    static void print_vec(const std::string& key, const std::vector<int>& v) {
        std::stringstream ss; ss << "[";
        for(size_t i=0; i<std::min((size_t)5, v.size()); ++i) ss << v[i] << ",";
        ss << "...] (len=" << v.size() << ")";
        print_kv(key, ss.str());
    }
    static void print_time(double ms) {
        std::cout << " [Time]: " << ms << " ms" << std::endl;
    }
};

class Timer {
    using Clock = std::chrono::high_resolution_clock;
    Clock::time_point start;
public:
    Timer() { start = Clock::now(); }
    double ms() {
        return std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start).count() / 1000.0;
    }
};

// --- 数学工具 ---
// 1. 字节转 Hex (修复命名冲突)
std::string bytes_to_hex(const std::vector<uint8_t>& d) {
    std::stringstream ss; ss << std::hex << std::setfill('0');
    for(auto b : d) ss << std::setw(2) << (int)b;
    return ss.str();
}

// 2. Vector<int> 序列化 (修复编译错误)
std::string vec_to_string(const std::vector<int>& v) {
    std::stringstream ss;
    for(auto x : v) ss << x << ",";
    return ss.str();
}

std::vector<uint8_t> H_Gen(const std::string& p, const std::string& s) {
    std::string d = p + s;
    std::vector<uint8_t> h(SHA256_DIGEST_LENGTH);
    SHA256((const uint8_t*)d.data(), d.size(), h.data());
    return h;
}
std::vector<uint8_t> H0(const std::string& s) { return H_Gen("H0", s); }
std::vector<uint8_t> H1(const std::string& s) { return H_Gen("H1", s); }
std::vector<uint8_t> H2(const std::string& s) { return H_Gen("H2", s); }
std::vector<uint8_t> H3(const std::string& s) { return H_Gen("H3", s); }

long long H_Int(const std::vector<uint8_t>& h) {
    long long r = 0; 
    for(int i=0; i<8; ++i) r = (r << 8) | h[i];
    return r & 0x7FFFFFFFFFFFFFFF; 
}

// --- LWE ---
struct LWEVector {
    std::vector<int> data;
    LWEVector(int n = LWE_N) : data(n, 0) {}
    
    static LWEVector from_seed(long long seed) {
        LWEVector v; std::mt19937 gen(seed);
        for(int& x : v.data) x = gen() % LWE_Q;
        return v;
    }
    static LWEVector random() { return from_seed(rand()); }
    
    int dot(const LWEVector& o) const {
        long long s = 0;
        for(int i=0; i<LWE_N; ++i) s += (long long)data[i] * o.data[i];
        return (s % LWE_Q + LWE_Q) % LWE_Q;
    }
    
    // 重命名为 scalar_mul (修复编译错误)
    LWEVector scalar_mul(int s) const {
        LWEVector r;
        for(int i=0; i<LWE_N; ++i) r.data[i] = (data[i] * s) % LWE_Q;
        return r;
    }
};

// --- CNF ---
class CNFParser {
public:
    static std::vector<std::vector<int>> parse(std::string p) {
        std::vector<std::vector<int>> g;
        std::stringstream ss(p); std::string seg;
        while(std::getline(ss, seg, '&')) {
            std::vector<int> cg;
            seg.erase(remove(seg.begin(), seg.end(), '('), seg.end());
            seg.erase(remove(seg.begin(), seg.end(), ')'), seg.end());
            std::stringstream ss2(seg); std::string d;
            while(std::getline(ss2, d, '|')) {
                try { cg.push_back(std::stoi(d)); } catch(...) {}
            }
            if(!cg.empty()) g.push_back(cg);
        }
        return g;
    }
};

// --- Secret Sharing ---
struct Poly {
    std::vector<long long> c;
    long long M = 1000000007;
    Poly(int d, long long s) {
        c.resize(d + 1); c[0] = s;
        for(int i=1; i<=d; ++i) c[i] = rand() % M;
    }
    long long eval(int x) {
        long long r = 0, p = 1;
        for(long long v : c) { r = (r + v * p) % M; p = (p * x) % M; }
        return r;
    }
};

long long lagrange(const std::map<int, long long>& pts) {
    long long M = 1000000007;
    auto inv = [&](long long n) {
        long long m0=M, y=0, x=1;
        if(M==1) return 0LL;
        while(n>1) {
            if(M==0) return 0LL;
            long long q=n/M, t=M; M=n%M; n=t; t=y; y=x-q*y; x=t;
        }
        if(x<0) x+=m0; return x;
    };
    long long s = 0;
    for(auto i : pts) {
        long long num=1, den=1;
        for(auto j : pts) {
            if(i.first == j.first) continue;
            num = (num * (-j.first + M)) % M;
            den = (den * (i.first - j.first + M)) % M;
        }
        if(den==0) continue;
        long long term = (i.second * num) % M;
        term = (term * inv(den)) % M;
        s = (s + term) % M;
    }
    return s;
}

// --- Net ---
void send_packet(tcp::socket& s, uint32_t t, const json& j) {
    std::string b = j.dump();
    uint32_t h[2] = {htonl(t), htonl(b.size())};
    std::vector<uint8_t> buf(8 + b.size());
    memcpy(buf.data(), h, 8); memcpy(buf.data()+8, b.data(), b.size());
    boost::asio::write(s, boost::asio::buffer(buf));
}
struct Packet { uint32_t type; json body; };
Packet read_packet(tcp::socket& s) {
    uint32_t h[2]; boost::asio::read(s, boost::asio::buffer(h, 8));
    uint32_t len = ntohl(h[1]);
    std::vector<char> b(len); boost::asio::read(s, boost::asio::buffer(b));
    return {ntohl(h[0]), json::parse(std::string(b.begin(), b.end()))};
}
