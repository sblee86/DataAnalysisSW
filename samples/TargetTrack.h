#pragma once
#define MAX_TARGETS 2
// Synthetic regression sample: nested helper is data, not an independent message.
typedef struct {
    uint16_t trackId;
    float x;
    float y;
} TrackEntry;

typedef struct {
    uint16_t id;
    uint16_t length;
    uint16_t valid : 5;
    uint16_t count : 11;
    TrackEntry tracks[MAX_TARGETS];
} TargetTrack;
