#include "Aethersight/Aethersight.h"
#include <tins/tins.h>
#include <pcap.h>
#include "Decompress.h"

using namespace Sapphire::Network::Packets;
using namespace Tins;

// Copied from Zanarkand
const std::string packetFilter("tcp portrange 54992-54994 or tcp portrange 55006-55007 or tcp portrange 55021-55040 or tcp portrange 55296-55551");

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

void BeginSniffing(PacketCallback callback, std::string deviceName) {
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_filter(packetFilter);
    config.set_buffer_size(16384);
    config.set_immediate_mode(true);

    if (deviceName == "") {
        auto device = NetworkInterface::default_interface();
        deviceName = device.name();
    }

    Sniffer sniffer(deviceName, config);

    // SnifferConfiguration::set_immediate_mode doesn't work for some reason; do it the old way
    auto handle = sniffer.get_pcap_handle();
    pcap_setmintocopy(handle, 0);
    pcap_set_timeout(handle, 1); // 1ms, setting this to 0 results in undefined behavior

    sniffer.sniff_loop([&](const Packet& packet) {
        return Process(packet, callback);
    });
}

void BeginSniffingFromFile(PacketCallback callback, std::string fileName) {
    FileSniffer sniffer(fileName, packetFilter);

    sniffer.sniff_loop([&](const Packet& packet) {
        return Process(packet, callback);
    });
}