#include "common.hpp"
#include <thread>

// ============================================================
// 安全问题（原型中硬编码；生产环境由用户输入）
// ============================================================
static const std::string SEC_QUESTIONS[N_SECURITY_Q] = {
    "What is your pet's name?",
    "What city were you born in?",
    "What is your mother's maiden name?"
};
static const std::string SEC_ANSWERS[N_SECURITY_Q] = {
    "fluffy", "beijing", "chen"
};

// ============================================================
// 智能卡数据结构
// ============================================================
struct SmartCard {
    // --- 从服务器注册响应获取 (SC*) ---
    long long sigma1;       // a1 = G(sigma1)
    long long d;            // d = a1*s_server + e_d
    long long Ri;           // Ri = HPW ^ p
    long long Ti;           // 模糊验证器
    long long H0_s;         // H_Int(H0(str(s)))，与服务器对齐
    int       N;            // 设备总数

    // --- 本地生成（注册时客户端计算）---
    long long b;            // 盐值
    long long h_pw_stored;  // HPW = H_Int(H0(pw+"|"+str(b)))，登录时复用
    std::string sigma_bio;  // Gen(Bio).first
    std::string theta_bio;  // Gen(Bio).second

    // 密钥恢复材料
    int       rec_x[N_SECURITY_Q];
    long long rec_delta[N_SECURITY_Q];
    std::string PWC_hex;    // AES256.Enc_{a0}(PW) 以 hex 存储

    // --- 会话临时状态 ---
    int s2_prime;           // 登录时生成，用于 Phase 5 解密

    // --------------------------------------------------------
    // store: 保存注册响应
    // --------------------------------------------------------
    void store(const json& j) {
        sigma1 = j["sigma1"];
        d      = j["d"];
        Ri     = j["Ri"];
        Ti     = j["Ti"];
        H0_s   = j["H0_s"];
        N      = j["N"];
    }

    // --------------------------------------------------------
    // Phase 3: 登录前本地验证 Ti*
    // 使用当前 PW 和存储的 b 计算 Ti*，与存储的 Ti 对比
    // --------------------------------------------------------
    bool verify_ti_local(const std::string& pw) const {
        long long HPW_now = compute_HPW(pw, b);
        long long MID_now = compute_MID(std::string("u1")); // uid 已知
        long long Ti_star = compute_Ti(HPW_now, MID_now);
        return Ti_star == Ti;
    }

    // --------------------------------------------------------
    // Phase 4: 构建认证请求
    // 输入：uid, pw, s_recon（重构的 s）
    // 输出：认证请求 JSON
    // --------------------------------------------------------
    json gen_verify_req(const std::string& uid, const std::string& pw, long long s_recon) {
        long long HPW = compute_HPW(pw, b);
        h_pw_stored   = HPW;

        long long mu1 = H_Int(H0(std::to_string(s_recon)));
        LWEVector a1  = LWEVector::from_seed(sigma1);

        // u1 = a1*s1' + e1'（带噪声 LWE 向量）
        int s1_p         = (int)(rng() % LWE_Q);
        LWEVector e1_vec = LWEVector::noise_vector();
        LWEVector u1     = a1.scalar_mul(s1_p).add(e1_vec);

        // c1' = d*s1' + e_c' + Encode(s)，然后 Comp
        int e_c    = lwe_noise();
        long long c1_raw = ((long long)d * s1_p + e_c + encode_msg(s_recon)) % LWE_Q;
        long long c1_bar = comp(c1_raw);

        // u2 = a2*s2' + e2'
        long long sigma2 = (long long)(rng() & 0x7FFFFFFFFFFFFFFF);
        LWEVector a2     = LWEVector::from_seed(sigma2);
        s2_prime         = (int)(rng() % LWE_Q);
        LWEVector e2_vec = LWEVector::noise_vector();
        LWEVector u2     = a2.scalar_mul(s2_prime).add(e2_vec);

        // p = Ri ^ HPW = H_Int(H0(s_server||ID||Treg))
        long long p      = Ri ^ HPW;
        // PID = H_Int(H0(uid)) ^ mu1 = MID ^ mu1
        long long MID    = compute_MID(uid);
        long long PID    = MID ^ mu1;

        long long Auth   = H_Int(H0(std::to_string(mu1) + vec_to_string(u2.data)));
        long long term   = H_Int(H0(vec_to_string(u1.data) + std::to_string(mu1)));
        long long REP    = (p ^ Auth) ^ term;

        std::string raw_Mi = std::to_string(mu1) + std::to_string(p) + std::to_string(PID) + std::to_string(REP);
        long long Mi       = H_Int(H0(raw_Mi));

        Logger::print_kv("p (auth factor)", p);
        Logger::print_kv("PID", PID);
        Logger::print_kv("REP", REP);

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

    // --------------------------------------------------------
    // Phase 5: 处理密钥协商响应，验证 Ms1，发送 ACK，输出会话密钥
    // --------------------------------------------------------
    bool process_auth_resp(const std::string& uid, long long s_recon,
                           const json& j, tcp::socket& sock) {
        long long mu1    = H_Int(H0(std::to_string(s_recon)));
        long long d2     = j["d2"];
        long long c2_bar = j["c2_bar"];

        // v2 = Decode(DeComp(c2_bar) - d2*s2')
        long long c2    = decomp(c2_bar);
        long long noise2 = ((long long)d2 * s2_prime) % LWE_Q;
        long long v2    = decode_msg((c2 - noise2 + LWE_Q * 2) % LWE_Q);
        long long mu2   = H_Int(H0(std::to_string(v2)));

        long long p     = Ri ^ h_pw_stored;

        std::string raw = uid + SERVER_ID
                        + std::to_string(mu1)
                        + std::to_string(d2)
                        + std::to_string(p)
                        + std::to_string(mu2);

        long long Ms1_calc = H_Int(H1(raw));
        long long Ms1_recv = j["Ms1"];

        Logger::print_kv("v2 (decrypted)", v2);
        Logger::print_kv("mu2", mu2);
        Logger::print_kv("Ms1 (recv)", Ms1_recv);
        Logger::print_kv("Ms1 (calc)", Ms1_calc);

        if (Ms1_calc != Ms1_recv) {
            Logger::print_kv("Server Auth", "FAIL");
            return false;
        }
        Logger::print_kv("Server Auth", "PASS");

        // 发送 ACK：Mu1 = H2(ID||SERVER_ID||mu1||d2||p||mu2)
        long long Mu1 = H_Int(H2(raw));
        json ack; ack["Mu1"] = Mu1;
        send_packet(sock, Msg_Phase5_AckReq, ack);

        // 计算会话密钥 sk = H3(ID||SERVER_ID||mu1||d2||p||mu2)
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
    std::string bio_input;
    std::cout << " Enter biometric (fingerprint string): ";
    std::cin >> bio_input; std::cin.ignore();

    // 1. 验证 ID（原型中 uid 已知）
    // 2. 用生物特征重现 sigma_bio，与存储值对比
    std::string sigma_check = rep_bio(bio_input, sc.theta_bio);
    if (sigma_check != sc.sigma_bio) {
        std::cout << " [FAIL] Biometric mismatch.\n";
        return;
    }
    Logger::print_kv("Biometric", "PASS");

    // 3. 用户回答安全问题，恢复 beta_i
    std::map<int, long long> pts;
    std::cout << " Answer security questions:\n";
    for (int i = 0; i < N_SECURITY_Q; ++i) {
        std::cout << "  Q" << (i+1) << ": " << SEC_QUESTIONS[i] << "\n  A: ";
        std::string ans; std::getline(std::cin, ans);
        long long beta_i = sc.rec_delta[i] ^ H_Int(H1(ans));
        pts[sc.rec_x[i]] = beta_i;
    }

    // 4. Lagrange 插值还原 a0 = f(0)
    long long a0_rec = lagrange(pts);
    Logger::print_kv("Recovered a0", a0_rec);

    // 5. AES 解密还原 PW
    auto pwc_bytes = hex_to_bytes(sc.PWC_hex);
    std::string pw_rec = aes256_decrypt(pwc_bytes, a0_rec);
    Logger::print_kv("Recovered PW", pw_rec);
}

// ============================================================
int main() {
    boost::asio::io_context ioc;
    std::string uid = "u1";
    std::string pw  = "123456";
    // 原型中生物特征固定；生产环境应由传感器读取
    std::string bio = "fingerprint_user1";

    // ===========================================================
    // Phase 2: 注册
    // ===========================================================
    std::cout << "Waiting for server to initialize...\n";
    std::this_thread::sleep_for(std::chrono::seconds(1));
    tcp::socket s_sock(ioc);
    s_sock.connect({boost::asio::ip::address::from_string("127.0.0.1"), SERVER_PORT});

    {
        Timer tmr;
        // 生成盐值 b
        sc.b = (long long)(rng() & 0x7FFFFFFFFFFFFFFF);
        long long HPW = compute_HPW(pw, sc.b);
        long long MID = compute_MID(uid);

        // 生物特征处理 Gen(Bio) = (sigma, theta)
        auto [sigma_bio, theta_bio] = gen_bio(bio);
        sc.sigma_bio = sigma_bio;
        sc.theta_bio = theta_bio;

        json req;
        req["uid"] = uid;
        req["HPW"] = HPW;
        req["MID"] = MID;
        send_packet(s_sock, Msg_Phase2_RegReq, req);
        Packet p = read_packet(s_sock);

        if (p.body.contains("error")) {
            std::cerr << "[Error] " << p.body["error"].get<std::string>() << "\n";
            return 1;
        }

        sc.store(p.body);
        sc.h_pw_stored = HPW;

        // 生成密钥恢复材料：degree-(N_SECURITY_Q-1) 多项式 f(x)，a0 = f(0)
        std::uniform_int_distribution<long long> dist(1, N0 - 1);
        long long a0 = dist(rng);
        Poly key_poly(N_SECURITY_Q - 1, a0);
        for (int i = 0; i < N_SECURITY_Q; ++i) {
            long long beta_i    = key_poly.eval(i + 1);
            sc.rec_x[i]         = i + 1;
            sc.rec_delta[i]     = beta_i ^ H_Int(H1(SEC_ANSWERS[i]));
        }
        sc.PWC_hex = bytes_to_hex(aes256_encrypt(pw, a0));

        Logger::print_phase("Phase 2: Registration (Client)");
        Logger::print_kv("b (salt)", sc.b);
        Logger::print_kv("HPW", HPW);
        Logger::print_kv("MID", MID);
        Logger::print_kv("Received Ri", sc.Ri);
        Logger::print_kv("Received Ti", sc.Ti);
        Logger::print_kv("Received N", (long long)sc.N);
        Logger::print_kv("PWC (hex)", sc.PWC_hex);
        Logger::print_time(tmr.ms());
    }

    std::cout << "\n--- Press Enter to login ---"; std::cin.ignore();

    // ===========================================================
    // Phase 3: 从设备获取份额
    // ===========================================================
    // 登录前先本地验证 Ti*
    if (!sc.verify_ti_local(pw)) {
        std::cerr << "[Error] Local Ti verification FAILED. Wrong password or corrupted card.\n";
        return 1;
    }
    Logger::print_kv("Local Ti check", "PASS");

    std::map<int, long long> pts;
    long long hpw = compute_HPW(pw, sc.b);
    {
        Timer tmr;
        Logger::print_phase("Phase 3: Share Collection (Client)");
        for (int i = 1; i <= sc.N; ++i) {
            try {
                tcp::socket d_sock(ioc);
                d_sock.connect({boost::asio::ip::address::from_string("127.0.0.1"),
                                (unsigned short)(DEVICE_BASE_PORT + i)});
                json q; q["uid"] = uid; q["hpw_seed"] = hpw;
                send_packet(d_sock, Msg_Phase3_FacReq, q);
                Packet r = read_packet(d_sock);
                if (r.body["ok"]) {
                    long long y = (long long)r.body["y_masked"] ^ hpw;
                    pts[r.body["x"]] = y;
                    std::cout << "  Dev" << i << " -> x=" << r.body["x"] << "\n";
                }
            } catch (const std::exception& e) {
                std::cout << "  Dev" << i << " failed: " << e.what() << "\n";
            }
        }
        Logger::print_time(tmr.ms());
    }

    if (pts.empty()) {
        std::cerr << "[Error] No shares collected.\n"; return 1;
    }

    long long s_recon = lagrange(pts);
    Logger::print_kv("Reconstructed s", s_recon);

    // ===========================================================
    // Phase 4: 认证请求
    // ===========================================================
    {
        Timer tmr;
        Logger::print_phase("Phase 4: Auth Request (Client)");
        json req4 = sc.gen_verify_req(uid, pw, s_recon);
        send_packet(s_sock, Msg_Phase4_VerifyReq, req4);
        Logger::print_time(tmr.ms());

        // Phase 5: 密钥协商
        Packet r5 = read_packet(s_sock);
        Timer tmr5;
        Logger::print_phase("Phase 5: Key Agreement (Client)");
        bool ok = sc.process_auth_resp(uid, s_recon, r5.body, s_sock);
        Logger::print_time(tmr5.ms());
        if (!ok) return 1;
    }

    // ===========================================================
    // 密码恢复演示（可选）
    // ===========================================================
    std::cout << "\n--- Press Enter for password recovery demo (or Ctrl+C to exit) ---";
    std::cin.ignore();
    password_recovery(uid);

    return 0;
}
