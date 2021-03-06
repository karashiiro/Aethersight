#ifndef AETHERSIGHT_AETHERSIGHT_H
#define AETHERSIGHT_AETHERSIGHT_H

#include <iostream>
#include <tins/tins.h>

#include "./Network/CommonNetwork.h"

#define DllExport __declspec( dllexport )

#define PktHeadSize sizeof(FFXIVARR_PACKET_HEADER)
#define SegHeadSize sizeof(FFXIVARR_PACKET_SEGMENT_HEADER)
#define IpcHeadSize sizeof(FFXIVARR_IPC_HEADER)

// Filter copied from Zanarkand
#define PACKET_FILTER "tcp portrange 54992-54994 or tcp portrange 55006-55007 or tcp portrange 55021-55040 or tcp portrange 55296-55551"

typedef void PacketCallback(
    std::string srcAddress,
    std::string dstAddress,
    const Aethersight::Network::FFXIVARR_PACKET_HEADER&,
    const Aethersight::Network::FFXIVARR_PACKET_SEGMENT_HEADER&,
    const Aethersight::Network::FFXIVARR_IPC_HEADER*,
    const std::vector<uint8_t>& remainder
);

namespace Aethersight {
    class DllExport AethersightSniffer {
    public:
        AethersightSniffer();

        void BeginSniffing(PacketCallback callback, std::string deviceName = "");
        void BeginSniffingFromFile(PacketCallback callback, std::string fileName);
        void EndSniffing();
        void EndSniffingFromFile();
    private:
        Tins::Sniffer* sniffer;
        Tins::FileSniffer* fileSniffer;

        bool Process(const Tins::Packet& packet, PacketCallback callback);
    };
}

extern "C" DllExport Aethersight::AethersightSniffer* CreateAethersightSniffer();

extern "C" DllExport void DisposeAethersightSniffer(Aethersight::AethersightSniffer* sniffer);

#endif //AETHERSIGHT_AETHERSIGHT_H
