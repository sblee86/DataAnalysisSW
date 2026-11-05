#pragma once
#pragma pack(push, 1)
typedef unsigned char UCHAR;
typedef unsigned short int USHORT;
using MessageId = unsigned long;
struct LegacyPacket {
    MessageId id;
    USHORT length;
    char label[4];
    UCHAR mode : 3, status : 5;
    const unsigned short int first, second;
    signed int delta;
    unsigned long long counter;
    long timestamp;
};
#pragma pack(pop)
