#include "common.hpp"
#include <thread>
#include <mutex>

struct UserDB {
    std::string ID;
    long long H0_s; 
    LWEVector a1; 
    LWEVector s_server; 
    long long Treg;     
};
std::map<std::string, UserDB> db;
std::mutex db_mutex;
long long global_s; 

class Connection : public std::enable_shared_from_this<Connection> {
    tcp::socket socket_;
public:
    Connection(tcp::socket socket) : socket_(std::move(socket)) {}
    void start() { do_read(); }
private:
    void do_read() {
        auto self(shared_from_this());
        std::thread([this, self](){
            try { Packet p = read_packet(socket_); handle(p); } catch(...) {}
        }).detach();
    }

    void handle(Packet p) {
        if (p.type == Msg_Phase2_RegReq) {
            Timer t;
            std::string uid = p.body["uid"];
            
            UserDB u; u.ID = uid;
            u.a1 = LWEVector::random();
            u.s_server = LWEVector::random(); 
            u.Treg = 123456789; 
            
            { std::lock_guard<std::mutex> l(db_mutex); u.H0_s = db["u1_init"].H0_s; }
            
            int d = u.a1.dot(u.s_server);
            
            // 修复：使用 vec_to_string
            std::string s_server_str = vec_to_string(u.s_server.data);
            long long h_server_secret = H_Int(H0(s_server_str + uid + std::to_string(u.Treg)));
            long long hpw = p.body["hpw"];
            long long Ri = hpw ^ h_server_secret;

            { std::lock_guard<std::mutex> l(db_mutex); db[uid] = u; }

            json resp;
            resp["a1"] = u.a1.data; resp["d"] = d; resp["Ri"] = Ri; resp["H0_s"] = u.H0_s;
            send_packet(socket_, Msg_Phase2_RegResp, resp);
            
            Logger::print_phase("阶段二: 注册 (Server)");
            Logger::print_kv("计算 d", d);
            Logger::print_kv("计算 Ri", Ri);
            Logger::print_time(t.ms());
            do_read(); 

        } else if (p.type == Msg_Phase4_VerifyReq) {
            Timer t;
            Logger::print_phase("阶段四: 身份验证 (Server)");
            
            std::string uid_claim = p.body["uid_claim"];
            UserDB user; { std::lock_guard<std::mutex> l(db_mutex); user = db[uid_claim]; }

            LWEVector u1; u1.data = p.body["u1"].get<std::vector<int>>();
            long long c1_p = p.body["c1_prime"];
            
            int noise = u1.dot(user.s_server);
            long long s_rec = (c1_p - noise + LWE_Q) % LWE_Q;
            long long mu1_star = H_Int(H0(std::to_string(s_rec)));
            
            Logger::print_kv("解密 s", s_rec);
            
            if (mu1_star != user.H0_s) {
                Logger::print_kv("结果", "FAIL (Secret Wrong)");
                return;
            }

            long long PID = p.body["PID"];
            long long REP = p.body["REP"];
            
            LWEVector u2; u2.data = p.body["u2"].get<std::vector<int>>();
            std::string u2_s = vec_to_string(u2.data);
            long long Auth = H_Int(H0(std::to_string(mu1_star) + u2_s));
            
            std::string u1_s = vec_to_string(u1.data);
            long long term = H_Int(H0(u1_s + std::to_string(mu1_star)));
            long long p_client = REP ^ Auth ^ term;

            // 修复：使用 vec_to_string
            std::string s_server_str = vec_to_string(user.s_server.data);
            long long p_local = H_Int(H0(s_server_str + user.ID + std::to_string(user.Treg)));

            if (p_client != p_local) {
                Logger::print_kv("认证因子验证", "FAIL");
                return;
            }
            Logger::print_kv("认证因子验证", "PASS");
            Logger::print_time(t.ms());

            // --- 阶段五 ---
            Timer t5;
            Logger::print_phase("阶段五: 密钥协商 (Server)");
            
            // 修正数学逻辑：
            // Server 选 s2 (向量), v2 (标量)
            LWEVector s2 = LWEVector::random(); 
            int v2 = rand() % LWE_Q;
            
            long long sigma2 = p.body["sigma2"];
            LWEVector a2 = LWEVector::from_seed(sigma2);
            
            // d2 = a2 * s2 (标量)
            int d2 = a2.dot(s2);
            
            // c2 = u2 * s2 + v2 (标量)
            int u2_dot_s2 = u2.dot(s2);
            long long c2 = (u2_dot_s2 + v2) % LWE_Q;

            long long mu2 = H_Int(H0(std::to_string(v2)));
            
            std::string raw = user.ID + std::to_string(mu1_star) + std::to_string(d2) + std::to_string(p_local) + std::to_string(mu2);
            long long Ms1 = H_Int(H1(raw));
            std::string sk_s = bytes_to_hex(H3(raw)); // 修复 hex

            Logger::print_kv("生成 v2", v2);
            Logger::print_kv("生成 LWE d2", d2);
            Logger::print_kv("生成 LWE c2", c2);
            Logger::print_kv("Server Key", sk_s);
            Logger::print_time(t5.ms());

            json resp; resp["Ms1"] = Ms1; resp["d2"] = d2; resp["c2"] = c2;
            send_packet(socket_, Msg_Phase5_AuthResp, resp);
            do_read();
        }
    }
};

void console_thread(boost::asio::io_context& ioc) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
    while(true) {
        int N;
        std::cout << "\n[系统] 请输入设备总数 N: ";
        if(!(std::cin >> N)) { std::cin.clear(); std::cin.ignore(); continue; }
        std::cin.ignore();
        
        while(true) {
            std::string p;
            std::cout << "[系统] 请输入访问结构 (如 1&2|3): ";
            std::getline(std::cin, p);
            if(p.empty()) continue;
            
            auto g = CNFParser::parse(p);
            bool err = false;
            for(auto& gr:g) for(int id:gr) if(id>N || id<1) err=true;
            if(err) { std::cout << "设备ID越界\n"; continue; }

            Timer t;
            global_s = 1234; 
            { std::lock_guard<std::mutex> l(db_mutex); db["u1_init"].H0_s = H_Int(H0(std::to_string(global_s))); }
            
            Poly poly(g.size()-1, global_s);
            Logger::print_phase("阶段一: 初始化分发");
            
            for(int i=0; i<g.size(); ++i) {
                int x = i+1; long long y = poly.eval(x);
                std::cout << "  Group " << i << " (x=" << x << ") Devices: ";
                for(int id : g[i]) {
                    std::cout << id << " ";
                    try {
                        tcp::socket s(ioc);
                        s.connect({boost::asio::ip::address::from_string("127.0.0.1"), (unsigned short)(DEVICE_BASE_PORT+id)});
                        json j; j["uid"]="u1"; j["x"]=x; j["y"]=y;
                        send_packet(s, Msg_Phase1_Share, j);
                    } catch(...) {}
                }
                std::cout << std::endl;
            }
            Logger::print_time(t.ms());
            break; 
        }
    }
}

int main() {
    boost::asio::io_context ioc;
    tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), SERVER_PORT));
    auto sock = std::make_shared<tcp::socket>(ioc);
    std::function<void()> do_acc = [&](){
        acc.async_accept(*sock, [&](auto ec){
            if(!ec) std::make_shared<Connection>(std::move(*sock))->start();
            sock = std::make_shared<tcp::socket>(ioc);
            do_acc();
        });
    };
    do_acc();
    std::thread([&](){ console_thread(ioc); }).detach();
    ioc.run();
}
