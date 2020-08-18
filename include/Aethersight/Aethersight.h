#ifndef AETHERSIGHT_AETHERSIGHT_H
#define AETHERSIGHT_AETHERSIGHT_H

#include <iostream>

#include "Sapphire/Network/CommonNetwork.h"

typedef void PacketCallback (std::string,
                             std::string,
                             Sapphire::Network::Packets::FFXIVARR_PACKET_HEADER,
                             Sapphire::Network::Packets::FFXIVARR_PACKET_SEGMENT_HEADER,
                             const Sapphire::Network::Packets::FFXIVARR_IPC_HEADER*,
                             const std::vector<uint8_t>*);

void BeginSniffing(PacketCallback callback, std::string deviceName = "");

void BeginSniffingFromFile(PacketCallback callback, std::string fileName);

#endif //AETHERSIGHT_AETHERSIGHT_H
