#include "Aethersight/Aethersight.h"

#include <pcap.h>
#include "Decompress.h"

using namespace Sapphire::Network::Packets;
using namespace Tins;

AethersightSniffer::AethersightSniffer() {}

bool AethersightSniffer::Process(const Packet& packet, PacketCallback callback) {
    const auto& ip = packet.pdu()->rfind_pdu<IP>();
    const auto& tcp = packet.pdu()->rfind_pdu<TCP>();

    std::string srcAddress(ip.src_addr().to_string() + ':' + std::to_string(tcp.sport()));
    std::string dstAddress(ip.dst_addr().to_string() + ':' + std::to_string(tcp.dport()));

    const auto& raw = tcp.find_pdu<RawPDU>();
    if (!raw) return true;

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

void AethersightSniffer::BeginSniffing(PacketCallback callback, std::string deviceName) {
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_filter(PACKET_FILTER);
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

    sniffer.sniff_loop([&](const Packet& packet) {
        return Process(packet, callback);
    });
}

void AethersightSniffer::BeginSniffingFromFile(PacketCallback callback, std::string fileName) {
    this->fileSniffer = new FileSniffer(fileName, PACKET_FILTER);

    fileSniffer->sniff_loop([&](const Packet& packet) {
        return Process(packet, callback);
    });
}

void AethersightSniffer::EndSniffing() {
    if (!this->sniffer) return;

    this->sniffer->stop_sniff();
    delete sniffer;
    this->sniffer = nullptr;
}

void AethersightSniffer::EndSniffingFromFile() {
    if (!this->fileSniffer) return;

    this->fileSniffer->stop_sniff();
    delete fileSniffer;
    this->fileSniffer = nullptr;
}

AethersightSniffer* CreateAethersightSniffer() {
    return new AethersightSniffer();
}

void DisposeAethersightSniffer(AethersightSniffer* sniffer) {
    if (!sniffer) return;

    sniffer->EndSniffing();
    sniffer->EndSniffingFromFile();
    delete sniffer;
    sniffer = nullptr;
}