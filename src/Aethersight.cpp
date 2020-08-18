#include "Aethersight.h"
#include <tins/tins.h>
#include "Decompress.h"

using namespace Sapphire::Network::Packets;
using namespace Tins;

bool Process(const Packet& packet, PacketCallback callback) {
    const auto& ip = packet.pdu()->rfind_pdu<IP>();
    const auto& tcp = packet.pdu()->rfind_pdu<TCP>();

    std::string srcAddress(ip.src_addr().to_string() + ':' + std::to_string(tcp.sport()));
    std::string dstAddress(ip.dst_addr().to_string() + ':' + std::to_string(tcp.dport()));

    const auto& raw = tcp.find_pdu<RawPDU>();
    if (raw == nullptr) return true;

    const auto payload = raw->payload();

    FFXIVARR_PACKET_HEADER packetHeader;
    memcpy(&packetHeader, payload.data(), sizeof(FFXIVARR_PACKET_HEADER));

    auto payloadRemainder = std::vector<uint8_t>(payload.data() + sizeof(FFXIVARR_PACKET_HEADER), payload.data() + payload.size());
    if (packetHeader.isCompressed) {
        payloadRemainder = Decompress(payloadRemainder);
    }

    FFXIVARR_PACKET_SEGMENT_HEADER segmentHeader;
    memcpy(&segmentHeader, payloadRemainder.data(), sizeof(FFXIVARR_PACKET_SEGMENT_HEADER));

    FFXIVARR_IPC_HEADER ipcHeader;
    std::vector<uint8_t> ipcData;
    if (segmentHeader.type == FFXIVARR_SEGMENT_TYPE::SEGMENTTYPE_IPC) {
        memcpy(&ipcHeader, payloadRemainder.data() + sizeof(FFXIVARR_PACKET_SEGMENT_HEADER), sizeof(FFXIVARR_IPC_HEADER));

        ipcData = std::vector<uint8_t>(payloadRemainder.data() + sizeof(FFXIVARR_PACKET_SEGMENT_HEADER) + sizeof(FFXIVARR_IPC_HEADER),
                                       payloadRemainder.data() + payloadRemainder.size());

        callback(srcAddress, dstAddress, packetHeader, segmentHeader, &ipcHeader, &ipcData);
    } else {
        callback(srcAddress, dstAddress, packetHeader, segmentHeader, nullptr, nullptr);
    }

    return true;
}

void BeginSniffing(PacketCallback callback, SnifferKind kind, std::string deviceName, std::string fileName) {
    const std::string packetFilter("tcp portrange 54992-54994 or tcp portrange 55006-55007 or tcp portrange 55021-55040 or tcp portrange 55296-55551");

    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_filter(packetFilter);
    config.set_buffer_size(16384);
    config.set_immediate_mode(true);

    BaseSniffer* sniffer;
    switch (kind) {
        case Default:
            if (deviceName == "") {
                auto device = NetworkInterface::default_interface();
                deviceName = device.name();
            }
            sniffer = new Sniffer(deviceName, config);
            break;
        case File:
            sniffer = new FileSniffer(fileName, packetFilter);
            break;
        default:
            return;
    }

    sniffer->sniff_loop([&](const Packet& packet) {
        return Process(packet, callback);
    });

    delete sniffer;
}