#include <pcap>
#include <stdio>
#include <stdlib>

void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    printf("Got a packet\n");
}

int main() {
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name eth0
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", "eth0", errbuf);
        return(2);
    }

    // Step 2: Compile filter_exp into BPF psuedo-code
    char filter_exp[] = "icmp";
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    // Step 4: Close the handle
    pcap_close(handle);

    return 0;
}
