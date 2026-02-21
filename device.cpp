#include "common.hpp"

// ============================================================
// 辅助设备存储：uid -> [(clause_id, sub_secret)]
// 同一设备可属于多个子句，每个子句存一条记录
// key "__global__" 存储全局份额（Phase 1）
// ============================================================
std::map<std::string, std::vector<std::pair<int, long long>>> storage;
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
            // Phase 1: 接收并存储子句子秘密（可多次，对应多个子句）
            // --------------------------------------------------
            if (p.type == Msg_Phase1_Share) {
                std::string uid = p.body["uid"];
                int clause_id   = p.body["x"];    // x 字段复用为 clause_id
                long long y     = p.body["y"];
                storage[uid].emplace_back(clause_id, y);

                Logger::print_phase("Phase 1: Share Stored  [Device " + std::to_string(my_id) + "]");
                Logger::print_kv("uid",                uid);
                Logger::print_kv("clause_id",          (long long)clause_id);
                Logger::print_kv("sub_secret (y)",     y);

            // --------------------------------------------------
            // Phase 3: 按 clause_id 返回对应子秘密（HPW 掩码）
            // --------------------------------------------------
            } else if (p.type == Msg_Phase3_FacReq) {
                std::string uid    = p.body["uid"];
                long long hpw_seed = p.body["hpw_seed"];
                int clause_id      = p.body["clause_id"];

                Logger::print_phase("Phase 3: Share Request  [Device " + std::to_string(my_id) + "]");
                Logger::print_kv("uid",              uid);
                Logger::print_kv("clause_id",        (long long)clause_id);
                Logger::print_kv("hpw_seed (mask)",  hpw_seed);

                json r;
                bool found = false;
                for (auto& [cid, y] : storage["__global__"]) {
                    if (cid == clause_id) {
                        long long ym = y ^ hpw_seed;
                        Logger::print_kv("sub_secret (y)",     y);
                        Logger::print_kv("y_masked = y ^ HPW", ym);
                        r["ok"]       = true;
                        r["clause_id"] = cid;
                        r["y_masked"]  = ym;
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    Logger::print_kv("clause_id not found", "ERROR");
                    r["ok"] = false;
                }
                send_packet(s, Msg_Phase3_FacResp, r);
            }
        } catch (const std::exception& e) {
            std::cerr << "[Device " << my_id << "] error: " << e.what() << "\n";
        }
    }
}
