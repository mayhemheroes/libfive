#include <stdint.h>
#include <stdio.h>
#include <climits>
#include "libfive.h"

#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString();
    const char* cstr = str.c_str();

    libfive_opcode_enum(cstr);
    return 0;
}
