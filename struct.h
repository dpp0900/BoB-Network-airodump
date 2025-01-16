#pragma pack(1)

typedef struct Display_info{
    uint8_t bss_id[6];
    int power;
    int beacons;
    int channel;
    struct Display_info* next;
    char* essid;
} Display_info;

typedef struct{
	uint8_t version;
	uint8_t pad;
	uint16_t len;
    uint32_t* present;
} Radio_tap_header;
//present의 마지막이 1일경우 다음 present가 존재


typedef struct {
    Radio_tap_header header;
    int8_t power;
} Radio_tap;

#define MAX_PAYLOAD_SIZE 2312

typedef struct {
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t da[6];
    uint8_t sa[6];
    uint8_t bss_id[6];
    uint16_t sequence_control;
} MACHeader;

typedef struct Tagged{
    uint8_t tag_name;
    uint8_t tag_len;
    uint8_t* data;
    struct Tagged* next;
} Tagged;

typedef struct {
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capacity_info;
    Tagged* tag;
} FrameBody;

typedef struct {
    MACHeader header;
    FrameBody body;
} Beacon_Frame;

// beacon frame의 경우 0x8000

//tag ssid

//tag supported tates

// thread 새로 빼서 출력문이랑 정보 가져오는곳 분리, iwconfig 이용해서 채널 변경하며 hopping. 이를 통해 주기적으로 내용 출력

//탐지될때마다 beacon 증가

//sudo iwconfig mon0 channel 1

#pragma pack()
