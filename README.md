# Aethersight
A simple packet sniffer for FFXIV.

## Executable Usage
`aethersight [-f <filename>] [-d <network device name>]`

## Library Usage
Aethersight exposes two methods.

```c++
void BeginSniffing(PacketCallback callback, std::string deviceName = "");

void BeginSniffingFromFile(PacketCallback callback, std::string fileName);
```

`PacketCallback` is a typedef for the following call signature:
```c++
typedef void PacketCallback (std::string,
                             std::string,
                             Sapphire::Network::Packets::FFXIVARR_PACKET_HEADER,
                             Sapphire::Network::Packets::FFXIVARR_PACKET_SEGMENT_HEADER,
                             const Sapphire::Network::Packets::FFXIVARR_IPC_HEADER*,
                             const std::vector<uint8_t>*);
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
