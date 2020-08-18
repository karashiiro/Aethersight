#ifndef AETHERSIGHT_ZLIB_H
#define AETHERSIGHT_ZLIB_H

#include <vector>
#include <zlib.h>

std::vector<uint8_t> Decompress(std::vector<uint8_t>& input);

#endif //AETHERSIGHT_ZLIB_H
