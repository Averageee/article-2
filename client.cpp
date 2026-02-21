#include "common.hpp"
#include <thread>

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
        Logger::print_phase("Phase 3-Pre: Local Ti Verification (SmartCard)");
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

        int s1_p         = (int)(rng() % LWE_Q);
        LWEVector e1_vec = LWEVector::noise_vector();
        LWEVector u1     = a1.scalar_mul(s1_p).add(e1_vec);

        int e_c      = lwe_noise();
        long long c1_raw = ((long long)d * s1_p + e_c + encode_msg(s_recon)) % LWE_Q;
        long long c1_bar = comp(c1_raw);

        long long sigma2 = (long long)(rng() & 0x7FFFFFFFFFFFFFFF);
        LWEVector a2     = LWEVector::from_seed(sigma2);
        s2_prime         = (int)(rng() % LWE_Q);
        LWEVector e2_vec = LWEVector::noise_vector();
        LWEVector u2     = a2.scalar_mul(s2_prime).add(e2_vec);

        long long p   = Ri ^ HPW;
        long long PID = MID ^ mu1;

        long long Auth = H_Int(H0(std::to_string(mu1) + vec_to_string(u2.data)));
        long long term = H_Int(H0(vec_to_string(u1.data) + std::to_string(mu1)));
        long long REP  = (p ^ Auth) ^ term;

        std::string raw_Mi = std::to_string(mu1)+std::to_string(p)+std::to_string(PID)+std::to_string(REP);
        long long Mi = H_Int(H0(raw_Mi));

        Logger::print_phase("Phase 4: Auth Request (SmartCard)");
        Logger::print_kv("s_recon (input)",   s_recon);
        Logger::print_kv("mu1 = H0(s)",       mu1);
        Logger::print_kv("sigma1 (seed a1)",  sigma1);
        Logger::print_vec("a1 (first 6)",     a1.data);
        Logger::print_kv("s1'",               (long long)s1_p);
        Logger::print_vec("e1' (noise)",      e1_vec.data);
        Logger::print_vec("u1 = a1*s1'+e1'",  u1.data);
        Logger::print_kv("e_c' (noise)",      (long long)e_c);
        Logger::print_kv("c1' = d*s1'+ec+Enc(s)", c1_raw);
        Logger::print_kv("c1_bar = Comp(c1')", c1_bar);
        Logger::print_kv("sigma2 (seed a2)",  sigma2);
        Logger::print_vec("a2 (first 6)",     LWEVector::from_seed(sigma2).data);
        Logger::print_kv("s2'",               (long long)s2_prime);
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
        pkg["c1_bar"]    = c1_bar;
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
        long long c2_bar = j["c2_bar"];

        long long c2     = decomp(c2_bar);
        long long noise2 = ((long long)d2 * s2_prime) % LWE_Q;
        long long v2     = decode_msg((c2 - noise2 + LWE_Q * 2) % LWE_Q);
        long long mu2    = H_Int(H0(std::to_string(v2)));
        long long p      = Ri ^ h_pw_stored;

        std::string raw = uid + SERVER_ID
                        + std::to_string(mu1)
                        + std::to_string(d2)
                        + std::to_string(p)
                        + std::to_string(mu2);

        long long Ms1_calc = H_Int(H1(raw));
        long long Ms1_recv = j["Ms1"];

        Logger::print_phase("Phase 5: Key Agreement (SmartCard)");
        Logger::print_kv("d2 (received)",      d2);
        Logger::print_kv("c2_bar (received)",  c2_bar);
        Logger::print_kv("c2 = DeComp(c2_bar)", c2);
        Logger::print_kv("s2'",                (long long)s2_prime);
        Logger::print_kv("noise = d2*s2'",     noise2);
        Logger::print_kv("v2 = Decode(c2-noise)", v2);
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
// 密码恢复阶段
// ============================================================
void password_recovery(const std::string& uid) {
    Logger::print_phase("Password Recovery Phase");

    // ── 先收集所有用户输入，不计入计时 ──────────────────────────
    // Step 1: ID 验证输入
    std::string id_input;
    std::cout << " [Input] User ID (注册时使用的用户名): ";
    std::getline(std::cin, id_input);
    if (id_input != sc.uid_stored) {
        Logger::print_kv("ID input",  id_input);
        Logger::print_kv("ID stored", sc.uid_stored);
        Logger::print_kv("ID Check",  "FAIL");
        return;
    }

    // Step 2: 生物特征输入
    std::string bio_input;
    std::cout << " [Input] Biometric (注册时的生物特征字符串): ";
    std::getline(std::cin, bio_input);

    // Step 3: 安全问题答案输入
    std::string answers[N_SECURITY_Q];
    std::cout << " [Input] Answer security questions:\n";
    for (int i = 0; i < N_SECURITY_Q; ++i) {
        std::cout << "  Q" << (i+1) << ": " << SEC_QUESTIONS[i] << "\n  A: ";
        std::getline(std::cin, answers[i]);
    }

    // ── 所有输入已收集，从此处开始计时 ──────────────────────────
    Timer tmr_total;

    Logger::print_kv("ID input",  id_input);
    Logger::print_kv("ID stored", sc.uid_stored);
    Logger::print_kv("ID Check",  "PASS");

    // 生物特征验证（计算量在计时内）
    std::string theta_now = bytes_to_hex(H1("bio_theta|" + bio_input));
    Logger::print_kv("bio_input",               bio_input);
    Logger::print_kv("theta (stored, head)",    sc.theta_bio.substr(0, 16) + "...");
    Logger::print_kv("theta (computed, head)",  theta_now.substr(0, 16) + "...");

    std::string sigma_check = rep_bio(bio_input, sc.theta_bio);
    Logger::print_kv("sigma (computed)",  sigma_check.empty() ? "(mismatch)" : sigma_check);
    Logger::print_kv("sigma (stored SC)", sc.sigma_bio);
    if (sigma_check != sc.sigma_bio) {
        Logger::print_kv("Biometric", "FAIL");
        Logger::print_time(tmr_total.ms());
        return;
    }
    Logger::print_kv("Biometric", "PASS");

    // βi = δi ⊕ H1(H2(Ansi) || (H2(IDi) mod n0))
    long long id_binding = H_Int(H2(uid)) % N0;
    Logger::print_sep();
    Logger::print_kv("id_binding = H2(uid)%n0", id_binding);
    std::map<int, long long> pts;
    for (int i = 0; i < N_SECURITY_Q; ++i) {
        std::string mask_str = bytes_to_hex(H2(answers[i])) + std::to_string(id_binding);
        long long mask_val   = H_Int(H1(mask_str));
        long long beta_i     = sc.rec_delta[i] ^ mask_val;
        Logger::print_kv("  mask_" + std::to_string(i+1), mask_val);
        Logger::print_kv("  delta_" + std::to_string(i+1), sc.rec_delta[i]);
        Logger::print_kv("  beta_"  + std::to_string(i+1), beta_i);
        pts[sc.rec_x[i]] = beta_i;
    }

    long long a0_rec   = lagrange(pts);
    auto pwc_bytes     = hex_to_bytes(sc.PWC_hex);
    std::string pw_rec = aes256_decrypt(pwc_bytes, a0_rec);

    Logger::print_sep();
    Logger::print_kv("Recovered a0",  a0_rec);
    Logger::print_kv("PWC (hex)",     sc.PWC_hex);
    Logger::print_kv("Recovered PW",  pw_rec);
    Logger::print_time(tmr_total.ms());
}

// ============================================================
int main() {
    // 计时汇总
    double t_phase2 = 0, t_phase3 = 0, t_phase4 = 0, t_phase5 = 0;

    // -------------------------------------------------------
    // 用户交互式输入凭据
    // -------------------------------------------------------
    std::string uid, pw, bio;
    std::cout << "============================================================\n";
    std::cout << "  AuthSystem Client\n";
    std::cout << "============================================================\n";
    std::cout << " [Input] User ID      : "; std::getline(std::cin, uid);
    std::cout << " [Input] Password     : "; std::getline(std::cin, pw);
    std::cout << " [Input] Biometric    : "; std::getline(std::cin, bio);

    // 安全问题答案（注册阶段设置）
    std::string user_ans[N_SECURITY_Q];
    std::cout << "\n [Setup] Set security question answers for password recovery:\n";
    for (int i = 0; i < N_SECURITY_Q; ++i) {
        std::cout << "   Q" << (i+1) << ": " << SEC_QUESTIONS[i] << "\n   A: ";
        std::getline(std::cin, user_ans[i]);
    }

    // ===========================================================
    // Phase 2: 注册
    // ===========================================================
    std::cout << "\n Connecting to server...\n";
    boost::asio::io_context ioc;
    tcp::socket s_sock(ioc);
    s_sock.connect({boost::asio::ip::address::from_string("127.0.0.1"), SERVER_PORT});

    {
        Timer tmr;
        sc.uid_stored = uid;

        // 生成盐值 b 和 HPW
        sc.b           = (long long)(rng() & 0x7FFFFFFFFFFFFFFF);
        long long HPW  = compute_HPW(pw, sc.b);
        long long MID  = compute_MID(uid);

        // Gen(Bio)
        auto [sigma_bio, theta_bio] = gen_bio(bio);
        sc.sigma_bio = sigma_bio;
        sc.theta_bio = theta_bio;

        // 发送注册请求
        json req; req["uid"] = uid; req["HPW"] = HPW; req["MID"] = MID;
        send_packet(s_sock, Msg_Phase2_RegReq, req);
        Packet resp = read_packet(s_sock);

        if (resp.body.contains("error")) {
            std::cerr << "[Error] " << resp.body["error"].get<std::string>() << "\n";
            return 1;
        }
        sc.store(resp.body);
        sc.h_pw_stored = HPW;

        // 生成密钥恢复多项式 f(x)，a0 = f(0)
        std::uniform_int_distribution<long long> dist(1, N0 - 1);
        long long a0 = dist(rng);
        Poly key_poly(N_SECURITY_Q - 1, a0);
        // δi = βi ⊕ H1(H2(Ansi) || (H2(IDi) mod n0))  绑定 ID，防止跨用户冒用
        long long id_binding = H_Int(H2(uid)) % N0;
        for (int i = 0; i < N_SECURITY_Q; ++i) {
            long long beta_i   = key_poly.eval(i + 1);
            sc.rec_x[i]        = i + 1;
            std::string mask_str = bytes_to_hex(H2(user_ans[i]))
                                   + std::to_string(id_binding);
            sc.rec_delta[i]    = beta_i ^ H_Int(H1(mask_str));
        }
        sc.PWC_hex = bytes_to_hex(aes256_encrypt(pw, a0));

        t_phase2 = tmr.ms();

        // 输出全量变量
        Logger::print_phase("Phase 2: Registration (Client)");
        Logger::print_kv("uid",                uid);
        Logger::print_kv("pw",                 pw);
        Logger::print_kv("bio",                bio);
        Logger::print_sep();
        Logger::print_kv("b (salt)",           sc.b);
        Logger::print_kv("HPW = H0(pw|b)",     HPW);
        Logger::print_kv("MID = H0(uid)",      MID);
        Logger::print_kv("sigma_bio",          sigma_bio.substr(0,16) + "...");
        Logger::print_kv("theta_bio",          theta_bio.substr(0,16) + "...");
        Logger::print_sep();
        Logger::print_kv("a0 (poly secret)",   a0);
        Logger::print_kv("id_binding = H2(uid)%n0", id_binding);
        for (int i = 0; i < N_SECURITY_Q; ++i) {
            Logger::print_kv("  beta_"  + std::to_string(i+1) + " = f(" + std::to_string(i+1) + ")",
                             key_poly.eval(i+1));
            Logger::print_kv("  delta_" + std::to_string(i+1) + " = beta^H1(H2(ans)||id_binding)",
                             sc.rec_delta[i]);
        }
        Logger::print_kv("PWC = AES256_Enc(a0, pw)", sc.PWC_hex);
        Logger::print_sep();
        Logger::print_kv("[From Server] sigma1", sc.sigma1);
        Logger::print_kv("[From Server] d",      sc.d);
        Logger::print_kv("[From Server] Ri",     sc.Ri);
        Logger::print_kv("[From Server] Ti",     sc.Ti);
        Logger::print_kv("[From Server] H0_s",   sc.H0_s);
        Logger::print_kv("[From Server] N",      (long long)sc.N);
        Logger::print_kv("[From Server] CNF",    sc.cnf_str);
        Logger::print_time(t_phase2);
    }

    std::cout << "\n--- Press Enter to start login ---";
    { std::string dummy; std::getline(std::cin, dummy); }

    // ===========================================================
    // Phase 3: 本地 Ti 验证 + 份额收集
    // ===========================================================
    if (!sc.verify_ti_local(uid, pw)) {
        std::cerr << "[Error] Local Ti verification FAILED.\n"; return 1;
    }

    long long hpw = compute_HPW(pw, sc.b);
    {
        Timer tmr;
        // 按 CNF 访问结构，每个子句选一个可用设备，取回子秘密后加法重构 s
        auto clauses = CNFParser::parse(sc.cnf_str);
        Logger::print_phase("Phase 3: Share Collection (Client)");
        Logger::print_kv("HPW (used as mask)", hpw);
        Logger::print_kv("CNF (AS)",           sc.cnf_str);

        long long s_recon = 0;
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
                                         + " Dev"  + std::to_string(dev_id)
                                         + " y_masked", y_masked);
                        Logger::print_kv("Clause " + std::to_string(ci)
                                         + " sub_s = y_m^HPW", sub_s);
                        clause_ok = true;
                        break;   // 该子句已满足，跳转到下一个子句
                    }
                } catch (const std::exception& e) {
                    std::cout << "  Dev" << dev_id << " failed: " << e.what() << "\n";
                }
            }
            if (!clause_ok)
                std::cerr << "[Warn] Clause " << ci << " unsatisfied\n";
        }

        Logger::print_sep();
        Logger::print_kv("s_recon (additive mod Q)", s_recon);
        Logger::print_kv("H0(s_recon)",              H_Int(H0(std::to_string(s_recon))));
        t_phase3 = tmr.ms();
        Logger::print_time(t_phase3);

        // ===========================================================
        // Phase 4: 认证请求（包含网络往返）
        // ===========================================================
        Packet r5;
        {
            Timer tmr4;
            json req4 = sc.gen_verify_req(uid, pw, s_recon);
            send_packet(s_sock, Msg_Phase4_VerifyReq, req4);
            r5 = read_packet(s_sock);   // 等待服务器 Phase 5 响应
            t_phase4 = tmr4.ms();
            Logger::print_time(t_phase4);
        }

        // Phase 5: 客户端本地处理
        {
            Timer tmr5;
            bool ok = sc.process_auth_resp(uid, s_recon, r5.body, s_sock);
            t_phase5 = tmr5.ms();
            Logger::print_time(t_phase5);
            if (!ok) return 1;
        }
    }

    // 耗时汇总
    Logger::print_phase("Timing Summary");
    Logger::print_kv("Phase 2 (Registration)",    (long long)t_phase2);
    Logger::print_kv("Phase 3 (Share Collection)", (long long)t_phase3);
    Logger::print_kv("Phase 4 (Auth Request)",    (long long)t_phase4);
    Logger::print_kv("Phase 5 (Key Agreement)",   (long long)t_phase5);
    Logger::print_kv("Total (P2+P3+P4+P5) ms",
        (long long)(t_phase2 + t_phase3 + t_phase4 + t_phase5));

    // 密码恢复演示
    std::cout << "\n--- Press Enter for password recovery demo ---";
    { std::string dummy; std::getline(std::cin, dummy); }
    password_recovery(uid);

    return 0;
}
