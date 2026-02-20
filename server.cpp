#include "common.hpp"
#include <thread>
#include <atomic>

// ============================================================
// 全局状态
// ============================================================
constexpr int MAX_DEVICES = 16;

struct UserDB {
    long long MID;
    long long sigma1;
    long long d;
    long long Ti;
    long long p_stored;
    long long H0_s;     // 登录验证时使用
    int s_server;       // LWE 私钥
};

std::map<std::string, UserDB> db;
std::mutex db_mtx;

long long global_s  = 0;     // Phase1 后销毁
long long global_N  = 0;     // 辅助设备总数
long long global_H0s = 0;

std::atomic<bool> phase1_done{false};

// ============================================================
// TCP 连接处理
// ============================================================
struct Connection : std::enable_shared_from_this<Connection> {
    tcp::socket sock;
    explicit Connection(tcp::socket s) : sock(std::move(s)) {}

    void run() {
        try {
            // 同一 TCP 连接上循环处理：Phase 2 注册 → Phase 4/5 认证
            while (true) {
                Packet p = read_packet(sock);
                if (p.type == Msg_Phase2_RegReq) {
                    handle_reg(p);
                    // 继续等待同一连接上的 Phase 4 请求
                } else if (p.type == Msg_Phase4_VerifyReq) {
                    handle_verify(p);
                    break;  // 认证完成，关闭连接
                } else {
                    break;
                }
            }
        } catch (const boost::system::system_error& e) {
            // EOF 表示客户端正常关闭，不打印错误
            if (e.code() != boost::asio::error::eof)
                std::cerr << "[Server] Connection error: " << e.what() << "\n";
        } catch (const std::exception& e) {
            std::cerr << "[Server] Connection error: " << e.what() << "\n";
        }
    }

    // ----------------------------------------------------------
    // Phase 2: 注册
    // ----------------------------------------------------------
    void handle_reg(const Packet& p) {
        if (!phase1_done) {
            json r; r["error"] = "Phase 1 not complete";
            send_packet(sock, Msg_Phase2_RegResp, r);
            return;
        }
        Timer tmr;

        std::string uid = p.body["uid"];
        long long HPW   = p.body["HPW"];
        long long MID   = p.body["MID"];

        // 生成 σ1、a1、s_server
        long long sigma1 = (long long)(rng() & 0x7FFFFFFFFFFFFFFF);
        LWEVector a1     = LWEVector::from_seed(sigma1);
        int s_sv         = (int)(rng() % LWE_Q) + 1;
        LWEVector e_d    = LWEVector::noise_vector();

        // d = a1·s_server + e_d  (取向量首元素 mod Q)
        long long d = ((long long)a1.dot(LWEVector::from_seed(sigma1)) % LWE_Q
                       + (long long)s_sv + e_d.data[0] + LWE_Q) % LWE_Q;
        // 更精确：d = a1[0]*s_sv + e_d[0]
        d = ((long long)a1.data[0] * s_sv % LWE_Q + e_d.data[0] + LWE_Q) % LWE_Q;

        // Ti, p_stored, Ri
        long long Treg    = (long long)(rng() & 0x7FFFFFFFFFFFFFFF);
        long long Ti      = compute_Ti(HPW, MID);
        long long p_stored = H_Int(H0(std::to_string(s_sv)
                                    + std::to_string(MID)
                                    + std::to_string(Treg)));
        long long Ri = HPW ^ p_stored;

        {
            std::lock_guard<std::mutex> lk(db_mtx);
            db[uid] = {MID, sigma1, d, Ti, p_stored, global_H0s, s_sv};
        }

        double elapsed = tmr.ms();

        Logger::print_phase("Phase 2: Registration (Server)  uid=" + uid);
        Logger::print_kv("[From Client] uid",   uid);
        Logger::print_kv("[From Client] HPW",   HPW);
        Logger::print_kv("[From Client] MID",   MID);
        Logger::print_sep();
        Logger::print_kv("sigma1",              sigma1);
        Logger::print_vec("a1 = G(sigma1)",     a1.data);
        Logger::print_kv("s_server",            (long long)s_sv);
        Logger::print_vec("e_d (noise)",        e_d.data);
        Logger::print_kv("d = a1[0]*sv+e_d[0]", d);
        Logger::print_kv("Treg (timestamp)",    Treg);
        Logger::print_kv("Ti = H0(HPW^MID)",   Ti);
        Logger::print_kv("p_stored = H0(sv||MID||Treg)", p_stored);
        Logger::print_kv("Ri = HPW ^ p_stored", Ri);
        Logger::print_kv("H0_s (global)",       global_H0s);
        Logger::print_kv("N (devices)",         global_N);
        Logger::print_time(elapsed);

        json r;
        r["sigma1"] = sigma1;
        r["d"]      = d;
        r["Ri"]     = Ri;
        r["Ti"]     = Ti;
        r["H0_s"]   = global_H0s;
        r["N"]      = (int)global_N;
        send_packet(sock, Msg_Phase2_RegResp, r);
    }

    // ----------------------------------------------------------
    // Phase 4 + Phase 5: 验证 + 密钥协商
    // ----------------------------------------------------------
    void handle_verify(const Packet& p) {
        Timer tmr_total;
        std::string uid_claim = p.body["uid_claim"];
        std::vector<int> u1   = p.body["u1"].get<std::vector<int>>();
        std::vector<int> u2   = p.body["u2"].get<std::vector<int>>();
        long long c1_bar      = p.body["c1_bar"];
        long long sigma2      = p.body["sigma2"];
        long long PID         = p.body["PID"];
        long long REP         = p.body["REP"];
        long long Mi          = p.body["Mi"];

        Logger::print_phase("Phase 4: Verification (Server)  uid_claim=" + uid_claim);
        Logger::print_kv("uid_claim",   uid_claim);
        Logger::print_vec("u1",         u1);
        Logger::print_vec("u2",         u2);
        Logger::print_kv("c1_bar",      c1_bar);
        Logger::print_kv("sigma2",      sigma2);
        Logger::print_kv("PID",         PID);
        Logger::print_kv("REP",         REP);
        Logger::print_kv("Mi",          Mi);

        UserDB user;
        {
            std::lock_guard<std::mutex> lk(db_mtx);
            if (!db.count(uid_claim)) {
                json r; r["error"] = "user not found";
                send_packet(sock, Msg_Phase5_AuthResp, r);
                return;
            }
            user = db[uid_claim];
        }

        // LWE 解密 s
        LWEVector u1v(LWE_N); u1v.data = u1;
        long long c1     = decomp(c1_bar);
        long long noise  = ((long long)user.s_server * u1v.data[0] % LWE_Q + LWE_Q) % LWE_Q;
        long long s_recv = decode_msg((c1 - noise + LWE_Q * 2) % LWE_Q);
        long long mu1_star = H_Int(H0(std::to_string(s_recv)));

        // 用 mu1* 恢复 ID
        long long id_hash = PID ^ mu1_star;

        // 验证 Mi
        long long p_sv = user.p_stored;
        long long Auth = H_Int(H0(std::to_string(mu1_star) + vec_to_string(u2)));
        long long term = H_Int(H0(vec_to_string(u1) + std::to_string(mu1_star)));
        long long p_client = REP ^ Auth ^ term;
        long long Mi_calc = H_Int(H0(std::to_string(mu1_star)
                                   + std::to_string(p_client)
                                   + std::to_string(id_hash)
                                   + std::to_string(REP)));

        Logger::print_sep();
        Logger::print_kv("c1 = DeComp(c1_bar)", c1);
        Logger::print_kv("s_server",             (long long)user.s_server);
        Logger::print_kv("noise = sv*u1[0]",     noise);
        Logger::print_kv("s_recv = Decode(c1-noise)", s_recv);
        Logger::print_kv("mu1* = H0(s_recv)",   mu1_star);
        Logger::print_kv("H0_s (stored)",        user.H0_s);
        Logger::print_kv("H0_s match",           (mu1_star == user.H0_s) ? "YES" : "NO");
        Logger::print_kv("id_hash = PID^mu1*",  id_hash);
        Logger::print_kv("MID (stored)",         user.MID);
        Logger::print_kv("ID match",             (id_hash == user.MID) ? "YES" : "NO");
        Logger::print_kv("Auth = H0(mu1*|u2)",  Auth);
        Logger::print_kv("term = H0(u1|mu1*)",  term);
        Logger::print_kv("p_client (computed)", p_client);
        Logger::print_kv("p_stored",            p_sv);
        Logger::print_kv("p match",             (p_client == p_sv) ? "YES" : "NO");
        Logger::print_kv("Mi (computed)",        Mi_calc);
        Logger::print_kv("Mi (received)",        Mi);
        Logger::print_kv("Mi match",            (Mi_calc == Mi) ? "YES" : "NO");
        Logger::print_time(tmr_total.ms());

        if (id_hash != user.MID || p_client != p_sv) {
            Logger::print_kv("Auth Result", "FAIL");
            json r; r["error"] = "auth failed";
            send_packet(sock, Msg_Phase5_AuthResp, r);
            return;
        }
        Logger::print_kv("Auth Result", "PASS");

        // ===========================================================
        // Phase 5: 密钥协商（服务器端）
        // ===========================================================
        Timer tmr5;
        LWEVector u2v(LWE_N); u2v.data = u2;
        LWEVector a2    = LWEVector::from_seed(sigma2);
        int s2          = (int)(rng() % LWE_Q) + 1;
        LWEVector e2v   = LWEVector::noise_vector();
        LWEVector d2v   = a2.scalar_mul(s2).add(e2v);
        long long d2    = d2v.data[0];

        long long v2    = (long long)(rng() % LWE_Q);
        int e_c2        = lwe_noise();
        long long c2    = ((long long)u2v.data[0] * s2 % LWE_Q + e_c2 + encode_msg(v2)) % LWE_Q;
        long long c2_bar = comp(c2);

        long long mu2   = H_Int(H0(std::to_string(v2)));
        std::string raw = uid_claim + SERVER_ID
                        + std::to_string(mu1_star)
                        + std::to_string(d2)
                        + std::to_string(p_client)
                        + std::to_string(mu2);
        long long Ms1   = H_Int(H1(raw));
        std::string sk_s = bytes_to_hex(H3(raw));

        Logger::print_phase("Phase 5: Key Agreement (Server)");
        Logger::print_kv("sigma2",              sigma2);
        Logger::print_vec("a2 = G(sigma2)",     a2.data);
        Logger::print_kv("s2",                  (long long)s2);
        Logger::print_vec("e2 (noise)",         e2v.data);
        Logger::print_vec("d2 = a2*s2+e2",      d2v.data);
        Logger::print_kv("d2 (scalar)",         d2);
        Logger::print_kv("v2 (random)",         v2);
        Logger::print_kv("e_c2 (noise)",        (long long)e_c2);
        Logger::print_kv("c2 = u2[0]*s2+ec+Enc(v2)", c2);
        Logger::print_kv("c2_bar = Comp(c2)",   c2_bar);
        Logger::print_kv("mu2 = H0(v2)",        mu2);
        Logger::print_kv("p_client",            p_client);
        Logger::print_kv("mu1*",                mu1_star);
        Logger::print_kv("raw string",          raw.substr(0,40) + "...");
        Logger::print_kv("Ms1 = H1(raw)",       Ms1);
        Logger::print_kv("Session Key (sk_s)",  sk_s);
        Logger::print_time(tmr5.ms());

        json r5;
        r5["d2"]     = d2;
        r5["c2_bar"] = c2_bar;
        r5["mu2"]    = mu2;
        r5["Ms1"]    = Ms1;
        send_packet(sock, Msg_Phase5_AuthResp, r5);

        // 接收 ACK（Mu1）
        try {
            Packet ack = read_packet(sock);
            if (ack.type == Msg_Phase5_AckReq) {
                long long Mu1      = ack.body["Mu1"];
                long long Mu1_calc = H_Int(H2(raw));
                Logger::print_sep();
                Logger::print_kv("Mu1 (received)",  Mu1);
                Logger::print_kv("Mu1 (computed)",  Mu1_calc);
                Logger::print_kv("Mutual Auth",     (Mu1 == Mu1_calc) ? "PASS" : "FAIL");
            }
        } catch (...) {}
    }
};

// ============================================================
// 辅助：带重试的设备连接（最多 retry 次，间隔 delay_ms 毫秒）
// ============================================================
static bool send_share_to_device(int id, int x, long long y,
                                  int retries = 10, int delay_ms = 1000) {
    for (int attempt = 1; attempt <= retries; ++attempt) {
        try {
            boost::asio::io_context d_ioc;
            tcp::socket d_sock(d_ioc);
            d_sock.connect({boost::asio::ip::address::from_string("127.0.0.1"),
                            (unsigned short)(DEVICE_BASE_PORT + id)});
            json s_json; s_json["uid"] = "__global__"; s_json["x"] = x; s_json["y"] = y;
            send_packet(d_sock, Msg_Phase1_Share, s_json);
            return true;
        } catch (const std::exception&) {
            if (attempt < retries) {
                std::cout << "  [Wait] Device " << id
                          << " not ready, retry " << attempt << "/" << retries
                          << " in " << delay_ms << "ms...\n";
                std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
            }
        }
    }
    return false;
}

// ============================================================
// 控制台线程：Phase 1 — 分发份额
// ============================================================
void console_thread() {
    std::cout << "\n[Console] Enter total number of auxiliary devices: ";
    int N; std::cin >> N; std::cin.ignore();
    global_N = N;

    // 提示用户确保设备已启动
    std::cout << "[Console] Please start device 1~" << N
              << " (ports " << DEVICE_BASE_PORT + 1
              << "~" << DEVICE_BASE_PORT + N << ").\n"
              << "[Console] Press Enter when all devices are ready...";
    { std::string dummy; std::getline(std::cin, dummy); }

    Timer tmr;
    Logger::print_phase("Phase 1: Secret Sharing (Server)");

    global_s = (long long)(rng() % (LWE_Q - 1)) + 1;
    global_H0s = H_Int(H0(std::to_string(global_s)));

    Logger::print_kv("s (master secret)", global_s);
    Logger::print_kv("H0(s)",             global_H0s);
    Logger::print_kv("N (devices)",       global_N);

    // Shamir (k=N, n=N) — 每个设备一个份额，阈值 = N
    Poly sp(N - 1, global_s);
    Logger::print_sep();
    bool all_ok = true;
    for (int i = 1; i <= N; ++i) {
        long long y = sp.eval(i);
        Logger::print_kv("  Share dev" + std::to_string(i)
                         + " (x=" + std::to_string(i) + ")", y);
        if (send_share_to_device(i, i, y)) {
            Logger::print_kv("  -> Sent to Device " + std::to_string(i), "OK");
        } else {
            Logger::print_kv("  -> Device " + std::to_string(i), "FAILED (skipped)");
            all_ok = false;
        }
    }

    // 销毁主秘密
    Logger::print_sep();
    Logger::print_kv("s destroyed", "yes (set to 0)");
    global_s = 0;

    Logger::print_time(tmr.ms());
    if (all_ok) {
        phase1_done = true;
        std::cout << "[Server] Phase 1 done. Waiting for client registration...\n";
    } else {
        std::cerr << "[Server] Phase 1 INCOMPLETE: some devices unreachable.\n";
    }
}

// ============================================================
int main() {
    std::cout << "============================================================\n";
    std::cout << "  AuthSystem Server  (port " << SERVER_PORT << ")\n";
    std::cout << "============================================================\n";

    std::thread(console_thread).detach();

    boost::asio::io_context ioc;
    tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), SERVER_PORT));
    std::cout << "[Server] Listening...\n";

    while (true) {
        tcp::socket sock(ioc);
        acc.accept(sock);
        auto conn = std::make_shared<Connection>(std::move(sock));
        std::thread([conn]{ conn->run(); }).detach();
    }
}
