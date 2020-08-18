# Aethersight
A simple packet sniffer for FFXIV.

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
 - other libtins and/or WinPCap headers
 - zconf.h
 - zlib.h
```
Also remember to move the zlib DLL to the output directory.
