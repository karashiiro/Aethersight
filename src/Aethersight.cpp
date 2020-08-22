#include "Aethersight/Aethersight.h"

#include <iostream>
#include <pcap.h>
#include "Decompress.h"

using namespace Aethersight;
using namespace Aethersight::Network;
using namespace Tins;

bool IsMagical(FFXIVARR_PACKET_HEADER header) {
    return (header.unknown_0 == 16304822851840528978 && header.unknown_8 == 8486076352731294335)
        || (header.unknown_0 == 0 && header.unknown_8 == 0);
}

AethersightSniffer::AethersightSniffer() : sniffer(nullptr), fileSniffer(nullptr) {}

bool AethersightSniffer::Process(const Packet& packet, PacketCallback callback) {
    const auto& ip = packet.pdu()->rfind_pdu<IP>();
    const auto& tcp = packet.pdu()->rfind_pdu<TCP>();

    std::string srcAddress(ip.src_addr().to_string() + ':' + std::to_string(tcp.sport()));
    std::string dstAddress(ip.dst_addr().to_string() + ':' + std::to_string(tcp.dport()));

    const auto& raw = tcp.find_pdu<RawPDU>();
    if (!raw) return true;

    auto payload = raw->payload();
    auto* remainderBegin = payload.data();

    FFXIVARR_PACKET_HEADER packetHeader;
    memcpy(&packetHeader, remainderBegin, PktHeadSize);
    remainderBegin += PktHeadSize;

    if (!IsMagical(packetHeader)) return true;

    std::vector<uint8_t> payloadRemainder(remainderBegin, payload.data() + payload.size());
    if (packetHeader.isCompressed) {
        try {
            payloadRemainder = Decompress(payloadRemainder);
        } catch (const std::exception& e) {
#if _DEBUG
            std::cout << e.what() << std::endl;
#endif
            return true;
        }
    }
    remainderBegin = payloadRemainder.data();

    for (int i = 0; i < packetHeader.segmentCount; i++) {
        FFXIVARR_PACKET_SEGMENT_HEADER segmentHeader;
        memcpy(&segmentHeader, remainderBegin, SegHeadSize);
        remainderBegin += SegHeadSize;

        auto remainderSize = segmentHeader.size - SegHeadSize;

        FFXIVARR_IPC_HEADER* ipcHeader = nullptr;
        if (segmentHeader.type == FFXIVARR_SEGMENT_TYPE::SEGMENTTYPE_IPC) {
            ipcHeader = new FFXIVARR_IPC_HEADER();
            memcpy(ipcHeader, remainderBegin, IpcHeadSize);
            remainderBegin += IpcHeadSize;
            remainderSize -= IpcHeadSize;
        }

        std::vector<uint8_t> remainderData(remainderBegin, remainderBegin + remainderSize);
        callback(srcAddress, dstAddress, packetHeader, segmentHeader, ipcHeader, remainderData);
        delete ipcHeader;

        remainderBegin += remainderSize;
    }

    return true;
}

void AethersightSniffer::BeginSniffing(PacketCallback callback, std::string deviceName) {
    if (this->sniffer) return;

    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_filter(PACKET_FILTER);
    config.set_buffer_size(16384);
    config.set_immediate_mode(true);

    if (deviceName == "") {
        auto device = NetworkInterface::default_interface();
        deviceName = device.name();
    }

    this->sniffer = new Sniffer(deviceName, config);

    // SnifferConfiguration::set_immediate_mode doesn't work for some reason; do it the old way
    auto handle = this->sniffer->get_pcap_handle();
    pcap_setmintocopy(handle, 0);

    this->sniffer->sniff_loop([&](const Packet& packet) {
        return Process(packet, callback);
    });
}

void AethersightSniffer::BeginSniffingFromFile(PacketCallback callback, std::string fileName) {
    if (this->fileSniffer) return;

    this->fileSniffer = new FileSniffer(fileName, PACKET_FILTER);

    this->fileSniffer->sniff_loop([&](const Packet& packet) {
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

DllExport AethersightSniffer* CreateAethersightSniffer() {
    return new AethersightSniffer();
}

DllExport void DisposeAethersightSniffer(AethersightSniffer* sniffer) {
    if (!sniffer) return;

    sniffer->EndSniffing();
    sniffer->EndSniffingFromFile();
    delete sniffer;
    sniffer = nullptr;
}