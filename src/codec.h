#ifndef CODEC_CODEC_H
#define CODEC_CODEC_H

#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <uuid/uuid.h>

std::string b64_encode(std::span<const unsigned char> source);
std::vector<unsigned char> b64_decode(std::string_view b64);
std::string url_encode(std::string_view source);
std::string url_decode(std::string_view source);
std::string unhex(const uuid_t& token);

#endif // CODEC_CODEC_H
