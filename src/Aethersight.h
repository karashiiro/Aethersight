#ifndef AETHERSIGHT_AETHERSIGHT_H
#define AETHERSIGHT_AETHERSIGHT_H

#include <iostream>

#include "CommonNetwork.h"

typedef void PacketCallback (std::string,
                             std::string,
                             Sapphire::Network::Packets::FFXIVARR_PACKET_HEADER,
                             Sapphire::Network::Packets::FFXIVARR_PACKET_SEGMENT_HEADER,
                             const Sapphire::Network::Packets::FFXIVARR_IPC_HEADER*,
                             const std::vector<uint8_t>*);

enum SnifferKind {
    Default,
    File,
};

void BeginSniffing(PacketCallback callback, SnifferKind kind, std::string deviceName = "", std::string fileName = "");

#endif //AETHERSIGHT_AETHERSIGHT_H
