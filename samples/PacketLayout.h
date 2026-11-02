#ifndef DRAS_PACKET_LAYOUT_H
#define DRAS_PACKET_LAYOUT_H
#include <stdint.h>
#define CHANNELS 2
#pragma pack(push, 1)
typedef struct {
    uint16_t sequence;
    uint16_t mode : 3;
    uint16_t valid : 1;
    uint16_t count : 12;
    int16_t values[CHANNELS];
} TelemetryHeader;
struct Envelope {
    uint8_t version;
    TelemetryHeader telemetry;
    uint32_t timestamp;
};
#pragma pack(pop)
#endif
