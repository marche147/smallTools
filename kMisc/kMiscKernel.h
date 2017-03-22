#pragma once

#define KMISC_TAG "[MISC] "
#define KMISC_PRINT(s, ...)  DbgPrint(KMISC_TAG s, __VA_ARGS__)

#define MAX_DEVICE_NAME_LEN 0x2710000