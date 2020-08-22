#include <iostream>
#include <string>

#include "Aethersight/Aethersight.h"

using namespace Aethersight;
using namespace Aethersight::Network;

std::string Vector8ToString(const std::vector<uint8_t>& vec) {
    std::string output = "";
    for (auto& b : vec) {
        output.append(std::to_string(b));
        output += " ";
    }
    output.pop_back();
    return output;
}

void OnPacket(std::string srcAddress,
              std::string dstAddress,
              const FFXIVARR_PACKET_HEADER& packetHeader,
              const FFXIVARR_PACKET_SEGMENT_HEADER& segmentHeader,
              const FFXIVARR_IPC_HEADER* ipcHeader,
              const std::vector<uint8_t>& remainderData) {
    std::cout <<
    "src_address=" << srcAddress << ";" <<
    "dst_address=" << dstAddress << ";" <<

    "unknown_0=" << packetHeader.unknown_0 << ";" <<
    "unknown_8=" << packetHeader.unknown_8 << ";" <<
    "timestamp=" << packetHeader.timestamp << ";" <<
    "total_size=" << packetHeader.size << ";" <<
    "connection_type=" << packetHeader.connectionType << ";" <<
    "segment_count=" << packetHeader.segmentCount << ";" <<
    "unknown_20=" << std::to_string(packetHeader.unknown_20) << ";" <<
    "is_compressed=" << (packetHeader.isCompressed ? "true" : "false") << ";" <<
    "unknown_24=" << packetHeader.unknown_24 << ";" <<

    "segment_size=" << segmentHeader.size << ";" <<
    "source_actor=" << segmentHeader.source_actor << ";" <<
    "target_actor=" << segmentHeader.target_actor << ";" <<
    "segment_type=" << segmentHeader.type << ";";

    if (ipcHeader) {
        std::cout <<
        "ipc_type=" << ipcHeader->type << ";" <<
        "server_id=" << ipcHeader->serverId << ";" <<
        "ipc_timestamp=" << ipcHeader->timestamp << ";";
    }

    std::cout <<
    "remainder_data=" << Vector8ToString(remainderData) << ";"
    << std::endl;
}

int main(int argc, char *argv[]) {
    std::string* file = nullptr;
    std::string* device = nullptr;
    for (int i = 0; i < argc - 1; i++) {
        std::string arg(argv[i]);
        std::string av(argv[i + 1]);
        if (arg == "-f") {
            file = &av;
        } else if (arg == "-d") {
            device = &av;
        }
    }

    AethersightSniffer sniffer;
    if (!file) {
        if (!device) {
            sniffer.BeginSniffing(OnPacket);
        } else {
            sniffer.BeginSniffing(OnPacket, *device);
        }
    } else {
        sniffer.BeginSniffingFromFile(OnPacket, *file);
    }
}
