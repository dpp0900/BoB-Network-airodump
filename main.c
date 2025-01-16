#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/wireless.h>
#include <arpa/inet.h>
#include "struct.h"

void usage() {
    printf("syntax: my_dump <interface>\n");
    printf("sample: my_dump mon0\n");
}

void set_channel(const char *interface, int channel) {
    int sock;
    struct iwreq req;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, interface, IFNAMSIZ);

    req.u.freq.m = channel;
    req.u.freq.e = 0;
    req.u.freq.flags = IW_FREQ_FIXED;

    if (ioctl(sock, SIOCSIWFREQ, &req) < 0) {
        perror("Failed to set channel");
        close(sock);
        exit(EXIT_FAILURE);
    }

    close(sock);

    usleep(200000); // 0.2s
}

void push_di(Display_info* head_di ,Display_info* new_di) {
    Display_info* cur_di = head_di;
    while (cur_di->next != NULL) {
        if (memcmp(cur_di->next->bss_id, new_di->bss_id, 6) == 0) {
            cur_di->power = new_di->power;
            cur_di->beacons++;
            free(new_di);
            return;
        }
        cur_di = cur_di->next;
    }
    cur_di->next = new_di;
}

void free_di(Display_info* head_di) {
    Display_info* cur_di = head_di;
    while (cur_di != NULL) {
        Display_info* next_di = cur_di->next;
        free(cur_di);
        cur_di = next_di;
    }
}

int parse_beacon_frame(const u_int8_t* packet, Beacon_Frame* bf, int packet_len) {
    const u_int8_t* cur = packet;
    bf->header.frame_control = *(uint16_t*)(cur);

    if (bf->header.frame_control != htons(0x8000)) {
        return -1;
    }

    cur += 2;
    bf->header.duration_id = *(uint16_t*)(cur);
    cur += 2;
    memcpy(bf->header.da, cur, 6);
    cur += 6;
    memcpy(bf->header.sa, cur, 6);
    cur += 6;
    memcpy(bf->header.bss_id, cur, 6);
    cur += 6;
    bf->header.sequence_control = *(uint16_t*)(cur);
    cur += 2;

    bf->body.timestamp = *(uint64_t*)(cur);
    cur += 8;
    bf->body.beacon_interval = *(uint16_t*)(cur);
    cur += 2;
    bf->body.capacity_info = *(uint16_t*)(cur);
    cur += 2;

    bf->body.tag = NULL;
    Tagged* last_tag = NULL;

    while (cur - packet < packet_len) {
        Tagged* new_tag = (Tagged*)malloc(sizeof(Tagged));
        new_tag->tag_name = *(cur++);
        new_tag->tag_len = *(cur++);
        new_tag->data = (uint8_t*)malloc(new_tag->tag_len);
        memcpy(new_tag->data, cur, new_tag->tag_len);
        cur += new_tag->tag_len;
        new_tag->next = NULL;

        if (bf->body.tag == NULL) {
            bf->body.tag = new_tag;
            last_tag = new_tag;
        } else {
            last_tag->next = new_tag;
            last_tag = new_tag;
        }
    }

    return 1;
}

bool parse_radio_tap(const u_int8_t* packet, Radio_tap* rt) {
    const u_int8_t* cur = packet;
    rt->header.version = *(cur);
    rt->header.pad = *(cur + 1);
    rt->header.len = *(uint16_t*)(cur + 2);
    cur += 4;

    unsigned int present_counter = 0;
    rt->header.present = (uint32_t*)malloc(sizeof(uint32_t));
    rt->header.present[0] = *(uint32_t*)(cur);
    cur += 4;

    while (rt->header.present[present_counter] & 0x80000000) {
        present_counter++;
        rt->header.present = (uint32_t*)realloc(rt->header.present, sizeof(uint32_t) * (present_counter + 1));
        rt->header.present[present_counter] = *(uint32_t*)(cur);
        cur += 4;
    }

    unsigned int offset_to_power = 8 + 4 * present_counter;

    if (rt->header.present[0] & 0x00000001) offset_to_power += 8;  // TSFT
    if (rt->header.present[0] & 0x00000002) offset_to_power += 1;  // Flags
    if (rt->header.present[0] & 0x00000004) offset_to_power += 1;  // Rate
    if (rt->header.present[0] & 0x00000008) offset_to_power += 4;  // Channel
    if (rt->header.present[0] & 0x00000010) offset_to_power += 2;  // FHSS

    rt->power = *(int8_t*)(packet + offset_to_power);

    return true;
}

void free_radio_tap(Radio_tap* rt) {
    free(rt->header.present);
    free(rt);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    Display_info* head_di = (Display_info*)malloc(sizeof(Display_info));
    head_di->next = NULL;

    int channel = 1;

    while (1) {
        set_channel(dev, channel);
        printf("\n");
        printf("Now Channel : %d\n", channel);
        printf("BSS ID              Power  Beacons  Channel  ESSID\n");
        printf("---------------------------------------------------\n");
        Display_info* cur_di = head_di->next;
        while (cur_di != NULL) {
            printf("%02x:%02x:%02x:%02x:%02x:%02x  %-5d  %-7d  %-7d  %s\n",
                   cur_di->bss_id[0], cur_di->bss_id[1], cur_di->bss_id[2],
                   cur_di->bss_id[3], cur_di->bss_id[4], cur_di->bss_id[5],
                   cur_di->power, cur_di->beacons, cur_di->channel, cur_di->essid);
            cur_di = cur_di->next;
        }
        printf("\033[H\033[J");
        channel = (channel % 10) + 1;

        struct pcap_pkthdr* header;
        const u_int8_t* packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        Radio_tap* rt = (Radio_tap*)malloc(sizeof(Radio_tap));
        if (!parse_radio_tap(packet, rt)) {
            free(rt);
            continue;
        }

        Beacon_Frame* bf = (Beacon_Frame*)malloc(sizeof(Beacon_Frame));
        if (parse_beacon_frame(packet + rt->header.len, bf, header->caplen - rt->header.len) == -1) {
            free_radio_tap(rt);
            free(bf);
            continue;
        }

        Display_info* new_di = (Display_info*)malloc(sizeof(Display_info));
        memcpy(new_di->bss_id, bf->header.bss_id, 6);
        new_di->power = rt->power;
        new_di->beacons = 1;
        new_di->channel = channel;
        new_di->next = NULL;
        for (Tagged* cur_tag = bf->body.tag; cur_tag != NULL; cur_tag = cur_tag->next) {
            if (cur_tag->tag_name == 0) {
                new_di->essid = (char*)malloc(cur_tag->tag_len + 1);
                memcpy(new_di->essid, cur_tag->data, cur_tag->tag_len);
                new_di->essid[cur_tag->tag_len] = '\0';
                break;
            }
        }
        push_di(head_di, new_di);

        free_radio_tap(rt);
        free(bf);
    }

    free_di(head_di);
    pcap_close(handle);
    return 0;
}
