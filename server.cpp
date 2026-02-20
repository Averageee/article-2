#include "common.hpp"
#include <thread>
#include <mutex>
#include <atomic>

struct UserDB {
    std::string ID;
    long long   MID;
    long long   H0_s;
    long long   sigma1;
    LWEVector   s_server;
    long long   d;
    long long   Treg;
    long long   Ti;
    long long   p_stored;
};

std::map<std::string, UserDB> db;
std::mutex   db_mutex;
int          global_N = 0;
std::atomic<bool> phase1_done{false};

class Connection : public std::enable_shared_from_this<Connection> {
    tcp::socket socket_;
public:
    explicit Connection(tcp::socket socket) : socket_(std::move(socket)) {}
    void start() { do_read(); }
private:
    void do_read() {
        auto self(shared_from_this());
        std::thread([this, self]() {
            try { Packet pkt = read_packet(socket_); handle(pkt); }
            catch (...) {}
        }).detach();
    }

    void handle_reg(const json& body) {
        if (!phase1_done.load()) {
            json err; err["error"] = "Phase 1 not done yet.";
            send_packet(socket_, Msg_Phase2_RegResp, err);
            return;
        }
        Timer tmr;
        std::string uid = body["uid"];
        long long HPW   = body["HPW"];
        long long MID   = body["MID"];

        UserDB u;
        u.ID  = uid;
        u.MID = MID;
        u.Treg = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        u.sigma1      = (long long)(rng() & 0x7FFFFFFFFFFFFFFF);
        LWEVector a1  = LWEVector::from_seed(u.sigma1);
        u.s_server    = LWEVector::random();
        int e_d       = lwe_noise();
        u.d           = ((long long)a1.dot(u.s_server) + e_d + LWE_Q) % LWE_Q;

        u.Ti = compute_Ti(HPW, MID);

        std::string ss_str = vec_to_string(u.s_server.data);
        u.p_stored = H_Int(H0(ss_str + uid + std::to_string(u.Treg)));

        long long Ri = HPW ^ u.p_stored;

        long long h0s = 0;
        { std::lock_guard<std::mutex> lk(db_mutex); h0s = db["__init__"].H0_s; }
        u.H0_s = h0s;
        { std::lock_guard<std::mutex> lk(db_mutex); db[uid] = u; }

        json resp;
        resp["sigma1"] = u.sigma1;
        resp["d"]      = u.d;
        resp["Ri"]     = Ri;
        resp["Ti"]     = u.Ti;
        resp["H0_s"]   = u.H0_s;
        resp["N"]      = global_N;
        send_packet(socket_, Msg_Phase2_RegResp, resp);

        Logger::print_phase("Phase 2: Registration (Server)");
        Logger::print_kv("UID", uid);
        Logger::print_kv("sigma1", u.sigma1);
        Logger::print_kv("d", u.d);
        Logger::print_kv("Ti", u.Ti);
        Logger::print_kv("Ri", Ri);
        Logger::print_time(tmr.ms());
        do_read();
    }

    void handle_verify(const json& body) {
        Timer tmr;
        Logger::print_phase("Phase 4: Verification (Server)");

        std::string uid_claim = body["uid_claim"];
        UserDB user;
        {
            std::lock_guard<std::mutex> lk(db_mutex);
            if (!db.count(uid_claim)) { Logger::print_kv("Result", "FAIL (unknown uid)"); return; }
            user = db[uid_claim];
        }

        LWEVector u1; u1.data = body["u1"].get<std::vector<int>>();
        long long c1_bar  = body["c1_bar"];
        long long c1      = decomp(c1_bar);
        long long noise1  = (long long)u1.dot(user.s_server);
        long long s_rec   = decode_msg((c1 - noise1 % LWE_Q + LWE_Q * 2) % LWE_Q);
        long long mu1_star = H_Int(H0(std::to_string(s_rec)));

        Logger::print_kv("Decoded s", s_rec);
        if (mu1_star != user.H0_s) { Logger::print_kv("Result", "FAIL (Secret)"); return; }
        Logger::print_kv("mu1 check", "PASS");

        long long PID      = body["PID"];
        long long id_check = PID ^ mu1_star;
        if (id_check != user.MID) { Logger::print_kv("Result", "FAIL (ID)"); return; }
        Logger::print_kv("ID check", "PASS");

        LWEVector u2; u2.data = body["u2"].get<std::vector<int>>();
        long long REP = body["REP"];

        long long Auth     = H_Int(H0(std::to_string(mu1_star) + vec_to_string(u2.data)));
        long long term     = H_Int(H0(vec_to_string(u1.data) + std::to_string(mu1_star)));
        long long p_client = REP ^ Auth ^ term;

        if (p_client != user.p_stored) { Logger::print_kv("Auth factor p", "FAIL"); return; }
        Logger::print_kv("Auth factor p", "PASS");
        Logger::print_time(tmr.ms());

        Timer tmr5;
        Logger::print_phase("Phase 5: Key Agreement (Server)");

        long long sigma2 = body["sigma2"];
        LWEVector a2 = LWEVector::from_seed(sigma2);
        LWEVector s2 = LWEVector::random();

        int v2   = (int)(rng() % LWE_Q);
        int e2   = lwe_noise();
        int ec   = lwe_noise();

        long long d2     = ((long long)a2.dot(s2) + e2 + LWE_Q) % LWE_Q;
        long long c2_raw = ((long long)u2.dot(s2) + ec + encode_msg(v2) + LWE_Q) % LWE_Q;
        long long c2_bar = comp(c2_raw);
        long long mu2    = H_Int(H0(std::to_string(v2)));

        std::string raw = user.ID + SERVER_ID
                        + std::to_string(mu1_star)
                        + std::to_string(d2)
                        + std::to_string(user.p_stored)
                        + std::to_string(mu2);
        long long Ms1    = H_Int(H1(raw));
        std::string sk_s = bytes_to_hex(H3(raw));

        Logger::print_kv("v2", (long long)v2);
        Logger::print_kv("d2", d2);
        Logger::print_kv("c2_bar", c2_bar);
        Logger::print_kv("Server SK", sk_s);
        Logger::print_time(tmr5.ms());

        json resp5;
        resp5["Ms1"]    = Ms1;
        resp5["d2"]     = d2;
        resp5["c2_bar"] = c2_bar;
        send_packet(socket_, Msg_Phase5_AuthResp, resp5);

        try {
            Packet ack = read_packet(socket_);
            if (ack.type != Msg_Phase5_AckReq) {
                Logger::print_kv("ACK", "FAIL (wrong type)"); return;
            }
            long long Mu1_recv = ack.body["Mu1"];
            long long Mu1_calc = H_Int(H2(raw));
            if (Mu1_recv == Mu1_calc) {
                Logger::print_kv("ACK (Client Auth)", "PASS");
                Logger::print_kv("Authentication", "COMPLETE");
            } else {
                Logger::print_kv("ACK (Client Auth)", "FAIL");
            }
        } catch (...) {
            Logger::print_kv("ACK", "FAIL (read error)");
        }
        do_read();
    }

    void handle(Packet pkt) {
        if      (pkt.type == Msg_Phase2_RegReq)    handle_reg(pkt.body);
        else if (pkt.type == Msg_Phase4_VerifyReq) handle_verify(pkt.body);
    }
};

void console_thread() {
    std::this_thread::sleep_for(std::chrono::seconds(1));
    while (true) {
        int N;
        std::cout << "\n[System] Enter device count N: ";
        if (!(std::cin >> N)) { std::cin.clear(); std::cin.ignore(); continue; }
        std::cin.ignore();
        while (true) {
            std::string pol;
            std::cout << "[System] Enter access structure (e.g. 1&2 or 1|2&3): ";
            std::getline(std::cin, pol);
            if (pol.empty()) continue;
            auto g = CNFParser::parse(pol);
            bool err = false;
            for (auto& gr : g) for (int id : gr) if (id > N || id < 1) err = true;
            if (err) { std::cout << " [Error] Device ID out of range\n"; continue; }

            std::uniform_int_distribution<long long> dist(1, LWE_Q - 1);
            long long s = dist(rng);
            global_N    = N;
            { std::lock_guard<std::mutex> lk(db_mutex); db["__init__"].H0_s = H_Int(H0(std::to_string(s))); }

            Poly poly((int)g.size() - 1, s);
            Logger::print_phase("Phase 1: Secret Distribution");
            Logger::print_kv("H0(s) stored", H_Int(H0(std::to_string(s))));
            Timer tmr;
            for (size_t i = 0; i < g.size(); ++i) {
                int x = (int)i + 1;
                long long y = poly.eval(x);
                std::cout << "  Group " << i << " (x=" << x << ") Devices:";
                for (int id : g[i]) {
                    std::cout << " " << id;
                    try {
                        boost::asio::io_context out_ioc;
                        tcp::socket sock(out_ioc);
                        sock.connect({boost::asio::ip::address::from_string("127.0.0.1"),
                                     (unsigned short)(DEVICE_BASE_PORT + id)});
                        json j; j["uid"] = "u1"; j["x"] = x; j["y"] = y;
                        send_packet(sock, Msg_Phase1_Share, j);
                    } catch (const std::exception& e) {
                        std::cout << "[fail:" << e.what() << "]";
                    }
                }
                std::cout << "\n";
            }
            Logger::print_time(tmr.ms());
            phase1_done.store(true);
            std::cout << "[System] Phase 1 done. s destroyed. Client may now register.\n";
            break;
        }
    }
}

int main() {
    boost::asio::io_context ioc;
    tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), SERVER_PORT));
    auto sock = std::make_shared<tcp::socket>(ioc);
    std::function<void()> do_acc = [&]() {
        acc.async_accept(*sock, [&](auto ec) {
            if (!ec) std::make_shared<Connection>(std::move(*sock))->start();
            sock = std::make_shared<tcp::socket>(ioc);
            do_acc();
        });
    };
    do_acc();
    std::thread(console_thread).detach();
    ioc.run();
}
