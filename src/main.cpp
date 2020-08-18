#include <iostream>
#include <string>

#include "Aethersight.h"

using namespace Sapphire::Network::Packets;

std::string Vector8ToString(const std::vector<uint8_t> vec) {
    std::string output = "";
    for (auto& b : vec) {
        output.append(std::to_string(b));
        output += " ";
    }
    output.pop_back();
    return output;
}

int main() {
    BeginSniffing([](std::string srcAddress,
                     std::string dstAddress,
                     FFXIVARR_PACKET_HEADER packetHeader,
                     FFXIVARR_PACKET_SEGMENT_HEADER segmentHeader,
                     const FFXIVARR_IPC_HEADER* ipcHeader,
                     const std::vector<uint8_t>* ipcData) {
        std::cout << "src_address=" << srcAddress << ";";
        std::cout << "dst_address=" << dstAddress << ";";

        std::cout << "unknown_0=" << packetHeader.unknown_0 << ";";
        std::cout << "unknown_8=" << packetHeader.unknown_8 << ";";
        std::cout << "timestamp=" << packetHeader.timestamp << ";";
        std::cout << "total_size=" << packetHeader.size << ";";
        std::cout << "connection_type=" << packetHeader.connectionType << ";";
        std::cout << "count=" << packetHeader.count << ";";
        std::cout << "unknown_20=" << std::to_string(packetHeader.unknown_20) << ";";
        std::cout << "is_compressed=" << (packetHeader.isCompressed ? "true" : "false") << ";";
        std::cout << "unknown_24=" << packetHeader.unknown_24 << ";";

        std::cout << "segment_size=" << segmentHeader.size << ";";
        std::cout << "source_actor=" << segmentHeader.source_actor << ";";
        std::cout << "target_actor=" << segmentHeader.target_actor << ";";
        std::cout << "segment_type=" << segmentHeader.type << ";";

        if (ipcHeader != nullptr) {
            std::cout << "ipc_type=" << ipcHeader->type << ";";
            std::cout << "server_id=" << ipcHeader->serverId << ";";
            std::cout << "ipc_timestamp=" << ipcHeader->timestamp << ";";

            std::cout << "ipc_data=" << Vector8ToString(*ipcData) << ";";
        }

        std::cout << std::endl;
    }, SnifferKind::Default);
}
