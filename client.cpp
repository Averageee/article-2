#include "common.hpp"

struct SmartCard {
    LWEVector a1;
    int d;
    long long Ri, H0_s;
    int s2_prime_stored; // 客户端临时私钥 (标量)

    void store(const json& j) {
        a1.data = j["a1"].get<std::vector<int>>();
        d = j["d"]; Ri = j["Ri"]; H0_s = j["H0_s"];
    }

    json gen_verify_req(std::string uid, std::string pw, long long s_recon) {
        long long mu1 = H_Int(H0(std::to_string(s_recon)));
        
        int s1_p = rand() % LWE_Q;
        LWEVector u1 = a1.scalar_mul(s1_p);
        long long c1_p = ((long long)d * s1_p + s_recon) % LWE_Q;

        long long sigma2 = rand();
        LWEVector a2 = LWEVector::from_seed(sigma2);
        
        s2_prime_stored = rand() % LWE_Q;
        LWEVector u2 = a2.scalar_mul(s2_prime_stored);

        long long h_pw = H_Int(H0(pw));
        long long p = Ri ^ h_pw;
        long long PID = H_Int(H0(uid)) ^ mu1;
        
        std::string u2_s = vec_to_string(u2.data);
        long long Auth = H_Int(H0(std::to_string(mu1) + u2_s));
        
        std::string u1_s = vec_to_string(u1.data);
        long long term = H_Int(H0(u1_s + std::to_string(mu1)));
        
        long long REP = (p ^ Auth) ^ term;
        
        std::string raw_Mi = std::to_string(mu1) + std::to_string(p) + std::to_string(PID) + std::to_string(REP);
        long long Mi = H_Int(H0(raw_Mi));

        json pkg;
        pkg["uid_claim"] = uid;
        pkg["u1"] = u1.data; pkg["u2"] = u2.data; pkg["c1_prime"] = c1_p;
        pkg["sigma2"] = sigma2; pkg["PID"] = PID; pkg["REP"] = REP; pkg["Mi"] = Mi;
        
        Logger::print_kv("计算 p", p);
        Logger::print_kv("计算 REP", REP);
        return pkg;
    }

    void process_auth_resp(std::string uid, long long s, const json& j) {
        long long mu1 = H_Int(H0(std::to_string(s)));
        
        int d2 = j["d2"];
        long long c2 = j["c2"];
        
        // Decrypt: v2 = c2 - d2 * s2'
        long long noise = ((long long)d2 * s2_prime_stored) % LWE_Q;
        long long v2 = (c2 - noise + LWE_Q) % LWE_Q;
        
        long long mu2 = H_Int(H0(std::to_string(v2)));
        long long h_pw = H_Int(H0("123456")); 
        long long p = Ri ^ h_pw;

        std::string raw = uid + std::to_string(mu1) + std::to_string(d2) + std::to_string(p) + std::to_string(mu2);
        long long Ms1_calc = H_Int(H1(raw));
        
        Logger::print_kv("收到 d2", d2);
        Logger::print_kv("解密 v2", v2);
        Logger::print_kv("Ms1 (Recv)", j["Ms1"].get<long long>());
        Logger::print_kv("Ms1 (Calc)", Ms1_calc);

        if (Ms1_calc == j["Ms1"].get<long long>()) {
            std::string sk = bytes_to_hex(H3(raw));
            Logger::print_kv("Client Key", sk);
        } else {
            Logger::print_kv("结果", "Server 验证失败");
        }
    }
};

SmartCard sc;

int main() {
    boost::asio::io_context ioc;
    std::string uid = "u1";
    std::string pw = "123456";

    std::cout << "等待 Server 初始化..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(1));
    tcp::socket s_sock(ioc);
    s_sock.connect({boost::asio::ip::address::from_string("127.0.0.1"), SERVER_PORT});

    // --- 阶段二 ---
    {
        Timer t;
        json req; req["uid"] = uid; req["hpw"] = H_Int(H0(pw)); 
        send_packet(s_sock, Msg_Phase2_RegReq, req);
        Packet p = read_packet(s_sock);
        sc.store(p.body);
        Logger::print_phase("阶段二: 注册 (Client)");
        Logger::print_kv("收到 Ri", p.body["Ri"].get<long long>());
        Logger::print_time(t.ms());
    }

    std::cout << "\n--- 回车登录 ---"; std::cin.ignore();

    // --- 阶段三 ---
    std::map<int, long long> pts;
    long long hpw = H_Int(H0(pw));
    {
        Timer t;
        Logger::print_phase("阶段三: 份额获取 (Client)");
        for(int i=1; i<=5; ++i) {
            try {
                tcp::socket d_sock(ioc);
                d_sock.connect({boost::asio::ip::address::from_string("127.0.0.1"), (unsigned short)(DEVICE_BASE_PORT+i)});
                json q; q["uid"]=uid; q["hpw_seed"]=hpw;
                send_packet(d_sock, Msg_Phase3_FacReq, q);
                Packet r = read_packet(d_sock);
                if(r.body["ok"]) {
                    long long y = (long long)r.body["y_masked"] ^ hpw;
                    pts[r.body["x"]] = y;
                    std::cout << "  Dev" << i << " -> x=" << r.body["x"] << std::endl;
                }
            } catch(...) {}
        }
        Logger::print_time(t.ms());
    }
    
    long long s_recon = lagrange(pts);
    Logger::print_kv("重构 s", s_recon);

    // --- 阶段四 ---
    {
        Timer t;
        Logger::print_phase("阶段四: 认证请求 (Client)");
        json p = sc.gen_verify_req(uid, pw, s_recon);
        send_packet(s_sock, Msg_Phase4_VerifyReq, p);
        Logger::print_time(t.ms());

        // --- 阶段五 ---
        Packet r = read_packet(s_sock);
        Timer t5;
        Logger::print_phase("阶段五: 密钥协商 (Client)");
        sc.process_auth_resp(uid, s_recon, r.body);
        Logger::print_time(t5.ms());
    }
    return 0;
}
