#include <iomanip>
#include <stdexcept>

#include <openssl/evp.h>

#include "codec.h"

std::string b64_encode(std::span<const unsigned char> source)
{
    std::string b64((source.size() + 2UL) / 3UL * 4UL, ' ');
    if (EVP_EncodeBlock((unsigned char*)b64.data(),
        source.data(), source.size()) == -1)
    {
        throw std::runtime_error("B64 encode");
    }
    return b64;
}

std::vector<unsigned char> b64_decode(std::string_view b64)
{
    std::vector<unsigned char> result(3 * b64.size() / 4);
    if (EVP_DecodeBlock(
        result.data(), (unsigned char*)b64.data(), b64.size()) == -1)
    {
        throw std::runtime_error("B64 decode");
    }
    result.resize(result.size() -
        (b64.size() - 1UL - b64.find_last_not_of('=')));
    return result;
}

std::string url_encode(std::string_view source)
{
    std::string url;
    for (const auto& c : source)
    {
        if ((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            c == '-' || c == '_' || c == '.' || c == '!' || c == '~' ||
            c == '*' || c == '\'' || c == '(' || c == ')')
        {
            url += c;
        }
        else if (c == ' ')
        {
            url += '+';
        }
        else
        {
            url += '%';
            unsigned char digit_1 = c / 16, digit_2 = c % 16;
            digit_1 += digit_1 <= 9 ? '0' : 'a' - 10;
            digit_2 += digit_2 <= 9 ? '0' : 'a' - 10;
            url += digit_1;
            url += digit_2;
        }
    }
    return url;
}

int char_decode(char c)
{
    return c <= '9' ? c - '0' : c < 'a' ? c - ('A' - 10) : c - ('a' - 10);
}

std::string url_decode(std::string_view source)
{
    std::string url;
    int hex_count = -1;
    unsigned char hex;
    for (const auto& c : source)
    {
        if (hex_count < 0)
        {
            if (c != '%')
            {
                if (c != '+')
                {
                    url += c;
                }
                else
                {
                    url += ' ';
                }
            }
            else
            {
                hex_count = 0;
            }
        }
        else if (hex_count == 0)
        {
            hex = 16 * char_decode(c);
            ++hex_count;
        }
        else
        {
            hex += char_decode(c);
            url += hex;
            hex_count = -1;
        }
    }
    return url;
}

std::string unhex(const uuid_t& token)
{
    std::ostringstream os;
    os << std::hex << std::setfill('0') << std::uppercase;
    for (const auto d : token)
    {
        os << std::setw(2) << static_cast<int>(d);
    }
    return std::move(os).str();
}
