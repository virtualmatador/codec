#include <iostream>

#include <codec.h>

int main()
{
    auto source = "{\"abc\": \"def\"}";
    auto encoded = url_encode(source);
    auto decoded = url_decode(encoded);
    if (decoded != source)
    {
        return -1;
    }
    return 0;
}
