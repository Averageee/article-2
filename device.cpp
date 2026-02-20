#include "common.hpp"

// ============================================================
// 辅助设备存储：uid -> { (x, y) }
// key "__global__" 存储全局份额（Phase 1）
// ============================================================
std::map<std::string, std::pair<int, long long>> storage;
int my_id;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: device <id>\n"; return 1;
    }
    my_id = std::stoi(argv[1]);
    unsigned short port = (unsigned short)(DEVICE_BASE_PORT + my_id);

    std::cout << "============================================================\n";
    std::cout << "  Device " << my_id << "  (port " << port << ")\n";
    std::cout << "============================================================\n";

    boost::asio::io_context ioc;
    tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), port));

    while (true) {
        tcp::socket s(ioc);
        acc.accept(s);
        try {
            Packet p = read_packet(s);

            // --------------------------------------------------
            // Phase 1: 接收并存储 Shamir 份额
            // --------------------------------------------------
            if (p.type == Msg_Phase1_Share) {
                std::string uid = p.body["uid"];
                int x           = p.body["x"];
                long long y     = p.body["y"];
                storage[uid]    = {x, y};

                Logger::print_phase("Phase 1: Share Stored  [Device " + std::to_string(my_id) + "]");
                Logger::print_kv("uid",             uid);
                Logger::print_kv("x (share index)", (long long)x);
                Logger::print_kv("y (share value)", y);

            // --------------------------------------------------
            // Phase 3: 响应客户端份额请求
            // --------------------------------------------------
            } else if (p.type == Msg_Phase3_FacReq) {
                std::string uid   = p.body["uid"];
                long long hpw_seed = p.body["hpw_seed"];

                Logger::print_phase("Phase 3: Share Request  [Device " + std::to_string(my_id) + "]");
                Logger::print_kv("uid",              uid);
                Logger::print_kv("hpw_seed (mask)",  hpw_seed);

                json r;
                std::string store_key = "__global__";   // 全局份额
                if (storage.count(store_key)) {
                    int x        = storage[store_key].first;
                    long long y  = storage[store_key].second;
                    long long ym = y ^ hpw_seed;

                    Logger::print_kv("Stored x",           (long long)x);
                    Logger::print_kv("Stored y",           y);
                    Logger::print_kv("y_masked = y ^ HPW", ym);

                    r["ok"]      = true;
                    r["x"]       = x;
                    r["y_masked"] = ym;
                } else {
                    Logger::print_kv("Share not found", "ERROR");
                    r["ok"] = false;
                }
                send_packet(s, Msg_Phase3_FacResp, r);
            }
        } catch (const std::exception& e) {
            std::cerr << "[Device " << my_id << "] error: " << e.what() << "\n";
        }
    }
}
