#include "common.hpp"
std::map<std::string, std::pair<int, long long>> storage;
int my_id;
int main(int argc, char* argv[]) {
    if(argc<2) return 1; my_id = std::stoi(argv[1]);
    boost::asio::io_context ioc;
    tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), DEVICE_BASE_PORT+my_id));
    std::cout << "Device " << my_id << " Port " << DEVICE_BASE_PORT+my_id << std::endl;
    while(true) {
        tcp::socket s(ioc); acc.accept(s);
        try {
            Packet p = read_packet(s);
            if(p.type==Msg_Phase1_Share) {
                storage[p.body["uid"]] = {p.body["x"], p.body["y"]};
                std::cout << "Store Share: x=" << p.body["x"] << " y=" << p.body["y"] << std::endl;
            } else if(p.type==Msg_Phase3_FacReq) {
                long long h = p.body["hpw_seed"];
                std::cout << "Req from client. H0(PW)=" << h << std::endl;
                json r;
                if(storage.count(p.body["uid"])) {
                    r["ok"]=true; r["x"]=storage[p.body["uid"]].first;
                    r["y_masked"]=storage[p.body["uid"]].second ^ h;
                } else r["ok"]=false;
                send_packet(s, Msg_Phase3_FacResp, r);
            }
        } catch(...) {}
    }
}
