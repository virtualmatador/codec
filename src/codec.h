#ifndef CODEC_CODEC_H
#define CODEC_CODEC_H

#include <span>
#include <string>
#include <vector>

#include <uuid/uuid.h>

std::string b64_encode(std::span<const unsigned char> source);
std::vector<unsigned char> b64_decode(const std::string& b64);
std::string url_encode(const std::string& source);
std::string unhex(const uuid_t& token);

#endif // CODEC_CODEC_H
