#include "common.hpp"
#include <thread>
#include <numeric>
#include <optional>

// ============================================================
// 安全问题（题目固定，答案由用户注册时设置）
// ============================================================
static const std::string SEC_QUESTIONS[N_SECURITY_Q] = {
    "What is your pet's name?",
    "What city were you born in?",
    "What is your mother's maiden name?"
};

// ============================================================
// 智能卡
// ============================================================
struct SmartCard {
    std::string uid_stored;   // 存 uid，供 Ti 本地验证使用
    long long sigma1;
    long long d;
    long long Ri;
    long long Ti;
    long long H0_s;
    int       N;
    std::string cnf_str;      // CNF 访问结构，Phase 3 按此选择设备

    long long b;
    long long h_pw_stored;
    std::string sigma_bio;
    std::string theta_bio;

    int       rec_x[N_SECURITY_Q];
    long long rec_delta[N_SECURITY_Q];
    std::string PWC_hex;

    int s2_prime;

    void store(const json& j) {
        sigma1  = j["sigma1"];
        d       = j["d"];
        Ri      = j["Ri"];
        Ti      = j["Ti"];
        H0_s    = j["H0_s"];
        N       = j["N"];
        cnf_str = j["cnf"].get<std::string>();
    }

    // 本地 Ti* 验证（登录前验证 PW 和 SC）
    bool verify_ti_local(const std::string& uid, const std::string& pw) const {
        long long HPW_now = compute_HPW(pw, b);
        long long MID_now = compute_MID(uid);
        long long Ti_star = compute_Ti(HPW_now, MID_now);
        Logger::print_phase("Phase 3: Ti Verification (SmartCard)");
        Logger::print_kv("b (salt)",            b);
        Logger::print_kv("HPW = H0(pw|b)",      HPW_now);
        Logger::print_kv("MID = H0(uid)",       MID_now);
        Logger::print_kv("Ti* (computed)",      Ti_star);
        Logger::print_kv("Ti  (stored on SC)",  Ti);
        bool ok = (Ti_star == Ti);
        Logger::print_kv("Ti Verification",     ok ? "PASS" : "FAIL");
        return ok;
    }

    // Phase 4: 构建认证请求，输出所有中间值
    json gen_verify_req(const std::string& uid, const std::string& pw, long long s_recon) {
        long long HPW = compute_HPW(pw, b);
        h_pw_stored   = HPW;
        long long MID = compute_MID(uid);

        long long mu1 = H_Int(H0(std::to_string(s_recon)));
        LWEVector a1  = LWEVector::from_seed(sigma1);

        int s1_p         = lwe_noise();                  // 小秘密 ∈ [-η, η]
        LWEVector e1_vec = LWEVector::noise_vector();
        LWEVector u1     = a1.scalar_mul(s1_p).add(e1_vec);

        // 逐 bit 编码 s_recon
        long long d_s1   = ((long long)d * s1_p % LWE_Q + LWE_Q) % LWE_Q;
        auto s_bits      = value_to_bits(s_recon);
        std::vector<long long> c1_arr(LWE_MSG_BITS);
        for (int j = 0; j < LWE_MSG_BITS; ++j) {
            int e_c_j        = lwe_noise();
            long long c1_j   = (d_s1 + e_c_j + encode_bit(s_bits[j]) + LWE_Q) % LWE_Q;
            c1_arr[j]        = comp(c1_j);
        }

        long long sigma2 = (long long)(rng() & 0x7FFFFFFFFFFFFFFF);
        LWEVector a2     = LWEVector::from_seed(sigma2);
        s2_prime         = lwe_noise();                  // 小秘密 ∈ [-η, η]
        LWEVector e2_vec = LWEVector::noise_vector();
        LWEVector u2     = a2.scalar_mul(s2_prime).add(e2_vec);

        long long p   = Ri ^ HPW;
        long long PID = MID ^ mu1;

        long long Auth = H_Int(H0(std::to_string(mu1) + vec_to_string(u2.data)));
        long long term = H_Int(H0(vec_to_string(u1.data) + std::to_string(mu1)));
        long long REP  = (p ^ Auth) ^ term;

        std::string raw_Mi = std::to_string(mu1)+std::to_string(p)+std::to_string(PID)+std::to_string(REP);
        long long Mi = H_Int(H0(raw_Mi));

        Logger::print_phase("Phase 3 (cont): Build Auth Request (SmartCard)");
        Logger::print_kv("s_recon (input)",   s_recon);
        Logger::print_kv("mu1 = H0(s)",       mu1);
        Logger::print_kv("sigma1 (seed a1)",  sigma1);
        Logger::print_vec("a1 (first 6)",     a1.data);
        Logger::print_kv("s1' (small)",       (long long)s1_p);
        Logger::print_vec("e1' (noise)",      e1_vec.data);
        Logger::print_vec("u1 = a1*s1'+e1'",  u1.data);
        Logger::print_kv("c1_arr (bits)",     (long long)c1_arr.size());
        Logger::print_kv("sigma2 (seed a2)",  sigma2);
        Logger::print_vec("a2 (first 6)",     LWEVector::from_seed(sigma2).data);
        Logger::print_kv("s2' (small)",       (long long)s2_prime);
        Logger::print_vec("e2' (noise)",      e2_vec.data);
        Logger::print_vec("u2 = a2*s2'+e2'",  u2.data);
        Logger::print_kv("HPW = H0(pw|b)",    HPW);
        Logger::print_kv("p = Ri ^ HPW",      p);
        Logger::print_kv("MID = H0(uid)",     MID);
        Logger::print_kv("PID = MID ^ mu1",   PID);
        Logger::print_kv("Auth = H0(mu1|u2)", Auth);
        Logger::print_kv("term = H0(u1|mu1)", term);
        Logger::print_kv("REP = (p^Auth)^term", REP);
        Logger::print_kv("Mi  = H0(mu1||p||PID||REP)", Mi);

        json pkg;
        pkg["uid_claim"] = uid;
        pkg["u1"]        = u1.data;
        pkg["u2"]        = u2.data;
        pkg["c1_bar"]    = c1_arr;
        pkg["sigma2"]    = sigma2;
        pkg["PID"]       = PID;
        pkg["REP"]       = REP;
        pkg["Mi"]        = Mi;
        return pkg;
    }

    // Phase 5: 验证 Ms1，发送 ACK，输出会话密钥
    bool process_auth_resp(const std::string& uid, long long s_recon,
                           const json& j, tcp::socket& sock) {
        long long mu1    = H_Int(H0(std::to_string(s_recon)));
        long long d2     = j["d2"];
        auto c2_bar_arr  = j["c2_bar"].get<std::vector<long long>>();

        // 逐 bit 解密 v2
        long long base_noise2 = ((long long)d2 * s2_prime % LWE_Q + LWE_Q) % LWE_Q;
        std::vector<int> v2_bits(LWE_MSG_BITS);
        for (int bj = 0; bj < LWE_MSG_BITS; ++bj) {
            long long c2_j = decomp(c2_bar_arr[bj]);
            long long val  = ((c2_j - base_noise2) % LWE_Q + LWE_Q) % LWE_Q;
            v2_bits[bj]    = decode_bit(val);
        }
        long long v2     = bits_to_value(v2_bits);
        long long mu2    = H_Int(H0(std::to_string(v2)));
        long long p      = Ri ^ h_pw_stored;

        std::string raw = uid + SERVER_ID
                        + std::to_string(mu1)
                        + std::to_string(d2)
                        + std::to_string(p)
                        + std::to_string(mu2);

        long long Ms1_calc = H_Int(H1(raw));
        long long Ms1_recv = j["Ms1"];

        Logger::print_phase("Phase 4 (cont): Key Agreement (SmartCard)");
        Logger::print_kv("d2 (received)",       d2);
        Logger::print_kv("c2_bar (bits)",       (long long)c2_bar_arr.size());
        Logger::print_kv("s2' (small)",         (long long)s2_prime);
        Logger::print_kv("base_noise = d2*s2'", base_noise2);
        Logger::print_kv("v2 (bit-decoded)",    v2);
        Logger::print_kv("mu2 = H0(v2)",       mu2);
        Logger::print_kv("mu1 = H0(s)",        mu1);
        Logger::print_kv("p   = Ri ^ HPW",     p);
        Logger::print_kv("Ms1 (received)",     Ms1_recv);
        Logger::print_kv("Ms1 (computed)",     Ms1_calc);

        if (Ms1_calc != Ms1_recv) {
            Logger::print_kv("Server Auth", "FAIL");
            return false;
        }
        Logger::print_kv("Server Auth", "PASS");

        long long Mu1 = H_Int(H2(raw));
        Logger::print_kv("Mu1 (ACK) = H2(raw)", Mu1);
        json ack; ack["Mu1"] = Mu1;
        send_packet(sock, Msg_Phase5_AckReq, ack);

        std::string sk = bytes_to_hex(H3(raw));
        Logger::print_kv("Session Key (sk_u)", sk);
        return true;
    }
};

SmartCard sc;

// ============================================================
// Phase 5: 密码恢复（纯计算版，benchmark 用）
// ============================================================
double run_password_recovery_bench(const std::string& uid, const std::string& bio_input,
                                   const std::string answers[]) {
    Timer tmr;
    // ID 校验
    if (uid != sc.uid_stored) return tmr.ms();
    // 生物特征验证
    std::string sigma_check = rep_bio(bio_input, sc.theta_bio);
    if (sigma_check != sc.sigma_bio) return tmr.ms();
    // βi 恢复 + Lagrange + AES 解密
    long long id_binding = H_Int(H2(uid)) % N0;
    std::map<int, long long> pts;
    for (int i = 0; i < N_SECURITY_Q; ++i) {
        std::string mask_str = bytes_to_hex(H2(answers[i])) + std::to_string(id_binding);
        long long beta_i     = sc.rec_delta[i] ^ H_Int(H1(mask_str));
        pts[sc.rec_x[i]] = beta_i;
    }
    long long a0_rec   = lagrange(pts);
    auto pwc_bytes     = hex_to_bytes(sc.PWC_hex);
    std::string pw_rec = aes256_decrypt(pwc_bytes, a0_rec);
    return tmr.ms();
}

// ============================================================
// Phase 5: 密码恢复（交互版，完整流程用）
// ============================================================
void password_recovery_interactive(const std::string& uid) {
    Logger::print_phase("Phase 5: Password Recovery (密码恢复阶段)");

    // 收集所有用户输入（不计时）
    std::string id_input;
    std::cout << " [Input] User ID (注册时使用的用户名): ";
    std::getline(std::cin, id_input);

    std::string bio_input;
    std::cout << " [Input] Biometric (注册时的生物特征字符串): ";
    std::getline(std::cin, bio_input);

    std::string answers[N_SECURITY_Q];
    std::cout << " [Input] Answer security questions:\n";
    for (int i = 0; i < N_SECURITY_Q; ++i) {
        std::cout << "  Q" << (i+1) << ": " << SEC_QUESTIONS[i] << "\n  A: ";
        std::getline(std::cin, answers[i]);
    }

    // 计时开始
    Timer tmr;

    // Step 1: ID 校验
    Logger::print_kv("ID input",  id_input);
    Logger::print_kv("ID stored", sc.uid_stored);
    if (id_input != sc.uid_stored) {
        Logger::print_kv("ID Check", "FAIL"); return;
    }
    Logger::print_kv("ID Check", "PASS");

    // Step 2: 生物特征验证 Rep(Bio*, θ) ?= σ
    std::string sigma_check = rep_bio(bio_input, sc.theta_bio);
    Logger::print_kv("sigma (computed)",  sigma_check.empty() ? "(mismatch)" : sigma_check);
    Logger::print_kv("sigma (stored SC)", sc.sigma_bio);
    if (sigma_check != sc.sigma_bio) {
        Logger::print_kv("Biometric", "FAIL");
        Logger::print_time(tmr.ms());
        return;
    }
    Logger::print_kv("Biometric", "PASS");

    // Step 3: βi = δi ⊕ H1(H2(Ansi) || (H2(IDi) mod n0))
    long long id_binding = H_Int(H2(uid)) % N0;
    Logger::print_kv("id_binding", id_binding);
    std::map<int, long long> pts;
    for (int i = 0; i < N_SECURITY_Q; ++i) {
        std::string mask_str = bytes_to_hex(H2(answers[i])) + std::to_string(id_binding);
        long long mask_val   = H_Int(H1(mask_str));
        long long beta_i     = sc.rec_delta[i] ^ mask_val;
        Logger::print_kv("  beta_" + std::to_string(i+1), beta_i);
        pts[sc.rec_x[i]] = beta_i;
    }

    // Step 4: Lagrange 恢复 a0 → AES 解密恢复密码
    long long a0_rec   = lagrange(pts);
    auto pwc_bytes     = hex_to_bytes(sc.PWC_hex);
    std::string pw_rec = aes256_decrypt(pwc_bytes, a0_rec);

    double elapsed = tmr.ms();
    Logger::print_sep();
    Logger::print_kv("Recovered a0",  a0_rec);
    Logger::print_kv("PWC (hex)",     sc.PWC_hex);
    Logger::print_kv("Recovered PW",  pw_rec);
    Logger::print_time(elapsed);
}

// ============================================================
// 单轮指标
// ============================================================
struct RoundMetrics {
    double t2 = 0, t3 = 0, t4 = 0;       // ms
    size_t comm2 = 0, comm3 = 0, comm4 = 0; // bytes
};

// ============================================================
// 单轮 Phase 2→4 执行（共用逻辑）
// ============================================================
std::optional<RoundMetrics> run_one_round(
        const std::string& uid, const std::string& pw, const std::string& bio,
        const std::string user_ans[], boost::asio::io_context& ioc) {

    RoundMetrics m;

    // Phase 2: 注册
    tcp::socket s_sock(ioc);
    s_sock.connect({boost::asio::ip::address::from_string("127.0.0.1"), SERVER_PORT});
    {
        reset_byte_counters();
        Timer tmr;
        sc.uid_stored = uid;
        sc.b          = (long long)(rng() & 0x7FFFFFFFFFFFFFFF);
        long long HPW = compute_HPW(pw, sc.b);
        long long MID = compute_MID(uid);

        auto [sigma_bio, theta_bio] = gen_bio(bio);
        sc.sigma_bio = sigma_bio;
        sc.theta_bio = theta_bio;

        json req; req["uid"] = uid; req["HPW"] = HPW; req["MID"] = MID;
        send_packet(s_sock, Msg_Phase2_RegReq, req);
        Packet resp = read_packet(s_sock);

        if (resp.body.contains("error")) {
            std::cerr << "[Error] " << resp.body["error"].get<std::string>() << "\n";
            return std::nullopt;
        }
        sc.store(resp.body);
        sc.h_pw_stored = HPW;

        std::uniform_int_distribution<long long> dist(1, N0 - 1);
        long long a0 = dist(rng);
        Poly key_poly(N_SECURITY_Q - 1, a0);
        long long id_binding = H_Int(H2(uid)) % N0;
        for (int i = 0; i < N_SECURITY_Q; ++i) {
            long long beta_i     = key_poly.eval(i + 1);
            sc.rec_x[i]          = i + 1;
            std::string mask_str = bytes_to_hex(H2(user_ans[i]))
                                   + std::to_string(id_binding);
            sc.rec_delta[i]      = beta_i ^ H_Int(H1(mask_str));
        }
        sc.PWC_hex = bytes_to_hex(aes256_encrypt(pw, a0));
        m.t2 = tmr.ms();
        m.comm2 = g_bytes_sent + g_bytes_recv;

        Logger::print_phase("Phase 2: Registration (注册阶段)");
        Logger::print_kv("uid",              uid);
        Logger::print_kv("b (salt)",         sc.b);
        Logger::print_kv("HPW = H0(pw|b)",   HPW);
        Logger::print_kv("MID = H0(uid)",    MID);
        Logger::print_kv("[Server] sigma1",  sc.sigma1);
        Logger::print_kv("[Server] d",       sc.d);
        Logger::print_kv("[Server] Ri",      sc.Ri);
        Logger::print_kv("[Server] Ti",      sc.Ti);
        Logger::print_kv("[Server] CNF",     sc.cnf_str);
        Logger::print_time(m.t2);
    }

    // Phase 3: 登录阶段 = Ti 验证 + 份额收集 + 构建认证请求
    long long s_recon = 0;
    json req_auth;
    {
        reset_byte_counters();
        Timer tmr;

        if (!sc.verify_ti_local(uid, pw)) {
            std::cerr << "[Error] Ti verification FAILED.\n";
            return std::nullopt;
        }

        long long hpw = compute_HPW(pw, sc.b);
        auto clauses  = CNFParser::parse(sc.cnf_str);
        Logger::print_phase("Phase 3: Login (登录阶段)");
        Logger::print_kv("HPW (mask)", hpw);
        Logger::print_kv("CNF (AS)",   sc.cnf_str);

        for (int ci = 0; ci < (int)clauses.size(); ++ci) {
            bool clause_ok = false;
            for (int dev_id : clauses[ci]) {
                try {
                    tcp::socket d_sock(ioc);
                    d_sock.connect({boost::asio::ip::address::from_string("127.0.0.1"),
                                    (unsigned short)(DEVICE_BASE_PORT + dev_id)});
                    json q;
                    q["uid"]       = uid;
                    q["hpw_seed"]  = hpw;
                    q["clause_id"] = ci;
                    send_packet(d_sock, Msg_Phase3_FacReq, q);
                    Packet r = read_packet(d_sock);
                    if (r.body["ok"]) {
                        long long y_masked = r.body["y_masked"];
                        long long sub_s    = y_masked ^ hpw;
                        s_recon = (s_recon + sub_s) % LWE_Q;
                        Logger::print_kv("Clause " + std::to_string(ci)
                                         + " Dev" + std::to_string(dev_id)
                                         + " sub_s", sub_s);
                        clause_ok = true;
                        break;
                    }
                } catch (...) {}
            }
            if (!clause_ok)
                std::cerr << "[Warn] Clause " << ci << " unsatisfied\n";
        }
        Logger::print_kv("s_recon", s_recon);

        req_auth = sc.gen_verify_req(uid, pw, s_recon);
        m.t3 = tmr.ms();
        m.comm3 = g_bytes_sent + g_bytes_recv;
        Logger::print_time(m.t3);
    }

    // Phase 4: 验证 + 密钥协商
    {
        reset_byte_counters();
        Timer tmr;
        send_packet(s_sock, Msg_Phase4_VerifyReq, req_auth);
        Packet resp4 = read_packet(s_sock);

        if (resp4.body.contains("error")) {
            std::cerr << "[Error] " << resp4.body["error"].get<std::string>() << "\n";
            return std::nullopt;
        }

        if (!sc.process_auth_resp(uid, s_recon, resp4.body, s_sock)) {
            std::cerr << "[Error] Key agreement failed.\n";
            return std::nullopt;
        }
        m.t4 = tmr.ms();
        m.comm4 = g_bytes_sent + g_bytes_recv;
        Logger::print_time(m.t4);
    }

    return m;
}

// ============================================================
int main() {
    std::string uid, pw, bio;
    std::cout << "============================================================\n";
    std::cout << "  AuthSystem Client\n";
    std::cout << "============================================================\n";
    std::cout << " [Input] User ID      : "; std::getline(std::cin, uid);
    std::cout << " [Input] Password     : "; std::getline(std::cin, pw);
    std::cout << " [Input] Biometric    : "; std::getline(std::cin, bio);

    std::string user_ans[N_SECURITY_Q];
    std::cout << "\n [Setup] Set security question answers for password recovery:\n";
    for (int i = 0; i < N_SECURITY_Q; ++i) {
        std::cout << "   Q" << (i+1) << ": " << SEC_QUESTIONS[i] << "\n   A: ";
        std::getline(std::cin, user_ans[i]);
    }

    // ── 模式选择 ──────────────────────────────────────────────
    int mode = 0;
    std::cout << "\n [Mode] 0 = 完整交互流程 (含密码恢复输入)\n"
              << "        1 = Benchmark (N 轮自动运行, 输出平均时间)\n"
              << "        选择 > ";
    std::cin >> mode; std::cin.ignore();

    boost::asio::io_context ioc;

    // ===========================================================
    // Mode 0: 完整交互流程
    // ===========================================================
    if (mode == 0) {
        std::cout << " [Net]  Simulated one-way network delay (ms, 0=localhost): ";
        std::cin >> SIMULATED_DELAY_MS; std::cin.ignore();
        if (SIMULATED_DELAY_MS < 0) SIMULATED_DELAY_MS = 0;
        auto res = run_one_round(uid, pw, bio, user_ans, ioc);
        if (!res) return 1;

        Logger::print_phase("Timing Summary (Phase 2-4)");
        Logger::print_kv("Phase 2  注册阶段      (ms)", res->t2);
        Logger::print_kv("Phase 3  登录阶段      (ms)", res->t3);
        Logger::print_kv("Phase 4  验证+密钥协商 (ms)", res->t4);
        Logger::print_kv("Total    (P2+P3+P4)   (ms)", res->t2 + res->t3 + res->t4);

        // 密码恢复：用户实时输入 ID、生物特征、安全问题答案
        std::cout << "\n--- Press Enter for password recovery demo ---";
        { std::string dummy; std::getline(std::cin, dummy); }
        password_recovery_interactive(uid);

        return 0;
    }

    // ===========================================================
    // Mode 1: Benchmark
    // ===========================================================
    int bench_N = 1;
    std::cout << " [Bench] Number of rounds: ";
    std::cin >> bench_N; std::cin.ignore();
    if (bench_N < 1) bench_N = 1;

    std::cout << " [Bench] Simulated one-way network delay (ms, 0=localhost): ";
    std::cin >> SIMULATED_DELAY_MS; std::cin.ignore();
    if (SIMULATED_DELAY_MS < 0) SIMULATED_DELAY_MS = 0;

    struct NullBuf : std::streambuf {
        int overflow(int c) override { return c; }
    } null_buf;

    std::vector<double> t2_arr, t3_arr, t4_arr, t5_arr;
    std::vector<size_t> c2_arr, c3_arr, c4_arr;
    t2_arr.reserve(bench_N); t3_arr.reserve(bench_N);
    t4_arr.reserve(bench_N); t5_arr.reserve(bench_N);
    c2_arr.reserve(bench_N); c3_arr.reserve(bench_N); c4_arr.reserve(bench_N);

    for (int round = 0; round < bench_N; ++round) {
        std::cout << "\r [Round " << (round + 1) << "/" << bench_N << "]" << std::flush;

        std::streambuf* saved_buf = std::cout.rdbuf(&null_buf);
        auto res = run_one_round(uid, pw, bio, user_ans, ioc);
        std::cout.rdbuf(saved_buf);

        if (!res) {
            std::cerr << "\n[Error] Round " << (round+1) << " failed.\n";
            return 1;
        }

        std::cout.rdbuf(&null_buf);
        double t5 = run_password_recovery_bench(uid, bio, user_ans);
        std::cout.rdbuf(saved_buf);

        t2_arr.push_back(res->t2); t3_arr.push_back(res->t3); t4_arr.push_back(res->t4);
        c2_arr.push_back(res->comm2); c3_arr.push_back(res->comm3); c4_arr.push_back(res->comm4);
        t5_arr.push_back(t5);
    }

    std::cout << "\n";

    auto avg_d = [](const std::vector<double>& v) {
        return std::accumulate(v.begin(), v.end(), 0.0) / (double)v.size();
    };
    auto avg_z = [](const std::vector<size_t>& v) {
        double s = 0; for (auto x : v) s += x;
        return s / (double)v.size();
    };
    double a2 = avg_d(t2_arr), a3 = avg_d(t3_arr),
           a4 = avg_d(t4_arr), a5 = avg_d(t5_arr);
    double ac2 = avg_z(c2_arr), ac3 = avg_z(c3_arr), ac4 = avg_z(c4_arr);

    // ── 向 Server 请求服务器侧计时 + 存储信息 ──
    int saved_delay = SIMULATED_DELAY_MS;
    SIMULATED_DELAY_MS = 0;
    double sv_a2 = 0, sv_a4v = 0, sv_a4k = 0;
    size_t sv_storage = 0;
    try {
        tcp::socket sum_sock(ioc);
        sum_sock.connect({boost::asio::ip::address::from_string("127.0.0.1"), SERVER_PORT});
        json sq; sq["action"] = "summary";
        send_packet(sum_sock, Msg_BenchmarkSummary, sq);
        Packet sr = read_packet(sum_sock);
        sv_a2  = sr.body["avg_t2"].get<double>();
        sv_a4v = sr.body["avg_t4_verify"].get<double>();
        sv_a4k = sr.body["avg_t4_ka"].get<double>();
        sv_storage = sr.body["storage"].get<size_t>();
    } catch (const std::exception& e) {
        std::cerr << "[Warn] Failed to get server summary: " << e.what() << "\n";
    }
    SIMULATED_DELAY_MS = saved_delay;

    // ── 计算存储开销 ──
    size_t sc_storage = sizeof(long long) * 7 + sizeof(int) * 2
                      + 64 * 2
                      + sizeof(int) * N_SECURITY_Q
                      + sizeof(long long) * N_SECURITY_Q
                      + 32
                      + sc.cnf_str.size() + sc.uid_stored.size();
    size_t dev_storage = sizeof(int) + sizeof(long long);

    // ── 输出 ──
    Logger::print_phase("Client-side Timing  (N = " + std::to_string(bench_N) + ", delay = "
                        + std::to_string(SIMULATED_DELAY_MS) + "ms)");
    Logger::print_kv("Avg Phase 2  注册       (ms)", a2);
    Logger::print_kv("Avg Phase 3  登录       (ms)", a3);
    Logger::print_kv("Avg Phase 4  验证+密钥  (ms)", a4);
    Logger::print_kv("Avg Phase 5  密码恢复   (ms)", a5);
    Logger::print_sep();
    Logger::print_kv("Avg Total (P2-P5)      (ms)", a2 + a3 + a4 + a5);

    Logger::print_phase("Server-side Timing  (N = " + std::to_string(bench_N) + ")");
    Logger::print_kv("Avg Phase 2  注册       (ms)", sv_a2);
    Logger::print_kv("Avg Phase 4  验证       (ms)", sv_a4v);
    Logger::print_kv("Avg Phase 4  密钥协商   (ms)", sv_a4k);

    Logger::print_phase("Communication Cost  (per round, bytes)");
    Logger::print_kv("Phase 2  注册           ", (long long)std::llround(ac2));
    Logger::print_kv("Phase 3  登录           ", (long long)std::llround(ac3));
    Logger::print_kv("Phase 4  验证+密钥      ", (long long)std::llround(ac4));
    Logger::print_sep();
    Logger::print_kv("Total                   ", (long long)std::llround(ac2 + ac3 + ac4));

    Logger::print_phase("Storage Overhead  (bytes)");
    Logger::print_kv("Server (per user)       ", (long long)sv_storage);
    Logger::print_kv("SmartCard (client)      ", (long long)sc_storage);
    Logger::print_kv("Device (per share)      ", (long long)dev_storage);

    return 0;
}
