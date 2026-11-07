#pragma once
// DRAS resolves MessageHeader from the saved common-header definition.
struct TestPack {
    MessageHeader Header;
    char label[4];
    UCHAR mode : 3, status : 5;
    const unsigned short int first, second;
    signed int delta;
    unsigned long long counter;
    long timestamp;
};
