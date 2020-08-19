#include "Decompress.h"

#include <iostream>
#include <sstream>
#include <stdexcept>

#define CHUNK 16384

// Copied from https://gist.github.com/gomons/9d446024fbb7ccb6536ab984e29e154a with slight alterations
std::vector<uint8_t> Decompress(std::vector<uint8_t>& input) {
    z_stream zs;
    memset(&zs, 0, sizeof(zs));

    if (inflateInit(&zs) != Z_OK)
        throw(std::runtime_error("inflateInit failed while decompressing."));

    zs.next_in = (Bytef*)input.data();
    zs.avail_in = input.size();

    int ret;
    char outbuffer[CHUNK];
    std::vector<uint8_t> outvec;

    // get the decompressed bytes blockwise using repeated calls to inflate
    do {
        zs.next_out = reinterpret_cast<Bytef*>(outbuffer);
        zs.avail_out = sizeof(outbuffer);

        ret = inflate(&zs, 0);

        if (outvec.size() < zs.total_out) {
            // Made a notable alteration to the Gist here, we don't want leftover data on the last chunk
            for (int i = 0; i < sizeof(outbuffer) - zs.avail_out; i++) {
                outvec.push_back(outbuffer[i]);
            }
        }

    } while (ret == Z_OK);

    inflateEnd(&zs);

    if (ret != Z_STREAM_END) {          // an error occurred that was not EOF
        std::ostringstream oss;
        oss << "Exception during zlib compression: (" << ret << ") ";
        if (zs.msg != nullptr) {
            oss << zs.msg;
        }
        throw(std::runtime_error(oss.str()));
    }

    return outvec;
}