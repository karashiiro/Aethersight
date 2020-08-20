# Aethersight
A simple packet sniffer for FFXIV. Shouldn't require privilege escalation or a firewall exception on Windows.

## Executable Usage
`aethersight [-f <filename>] [-d <network device name>]`

## Library Usage
Aethersight exposes the following interface:

```c++
class DllExport AethersightSniffer {
    AethersightSniffer();

    void BeginSniffing(PacketCallback callback, const char* deviceName = "");
    void BeginSniffingFromFile(PacketCallback callback, const char* fileName);
    void EndSniffing();
    void EndSniffingFromFile();
}

extern "C" DllExport AethersightSniffer* CreateAethersightSniffer();

extern "C" DllExport void DisposeAethersightSniffer(AethersightSniffer* sniffer);
```

`PacketCallback` is a typedef for the following call signature:
```c++
typedef void (__stdcall* PacketCallback)(
    const char*,
    const char*,
    const Aethersight::Network::FFXIVARR_PACKET_HEADER*,
    const Aethersight::Network::FFXIVARR_PACKET_SEGMENT_HEADER*,
    const Aethersight::Network::FFXIVARR_IPC_HEADER*,
    const std::vector<uint8_t>*
);
```

To begin sniffing, simply call one of the two methods with a callback.

## Building
Aethersight depends on [libtins](http://libtins.github.io) and [zlib](https://zlib.net/). On Windows x64, a pre-built zlib can be acquired via `vcpkg`. The additional directory structure should look as follows:
```
lib/
 - tins.lib
 - winpcap.lib # If on Windows
 - zlib.lib
include/
 - pcap/
 - tins/
 - other libtins and WinPCap headers
 - zconf.h
 - zlib.h
```
Also remember to move the zlib DLL to the output directory.
