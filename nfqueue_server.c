#include <arpa/inet.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "tcp_pkt_struct.h"
// TEST COMMENT


/**
 * USE FOR DEBUGGING TO PRINT BINARY NUMBERS
 */
static void print_bin(uint8_t n) {
    for (int i = 0; i < 8; i++) {
        printf("%d", n % 2);
        n /= 2;
    }

}
uint16_t ipv4_checksum(struct iphdr *ipv4Header)
{
    const uint16_t *data = (const uint16_t *)ipv4Header;
    size_t len = sizeof(*ipv4Header);
    uint32_t checksum = 0;

    while (len > 1)
    {
        checksum += *data++;
        len -= 2;
    }

    if (len > 0)
        checksum += *(const uint8_t *)data;

    while (checksum >> 16)
        checksum = (checksum & 0xffff) + (checksum >> 16);

    return ~checksum;
}

static void send_socket(full_tcp_pkt_t *ipv4_packet) {
    int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    // sendto(raw_socket, ipv4_packet, ipv4_packet->ipv4_header.total_length, MSG_DONTROUTE, )
}
char *exec_cmd(char *command){
    FILE *pf;
    char *data = malloc(10000);


    // Setup our pipe for reading and execute our command.
    pf = popen(command,"r"); 

    // Error handling

    // Get the data from the process execution
    fgets(data, 10000 , pf);

    // the data is now in 'data'

    if (pclose(pf) != 0)
        fprintf(stderr," Error: Failed to close command stream \n");

    return data;
}

long ipcsum(unsigned char *buf, int length) {
    int i = 0;

    long sum = 0;
    long data;

    // Handle all pairs
    while (length > 1) {
        // Corrected to include @Andy's edits and various comments on Stack Overflow
        data = (((buf[i] << 8) & 0xFF00) | ((buf[i + 1]) & 0xFF));
        sum += data;
        // 1's complement carry bit correction in 16-bits (detecting sign extension)
        if ((sum & 0xFFFF0000) > 0) {
            sum = sum & 0xFFFF;
            sum += 1;
        }

        i += 2;
        length -= 2;
    }

    // Handle remaining byte in odd length buffers
    if (length > 0) {
        // Corrected to include @Andy's edits and various comments on Stack Overflow
        sum += (buf[i] << 8 & 0xFF00);
        // 1's complement carry bit correction in 16-bits (detecting sign extension)
        if ((sum & 0xFFFF0000) > 0) {
            sum = sum & 0xFFFF;
            sum += 1;
        }
    }

    // Final 1's complement value correction to 16-bits
    sum = ~sum;
    sum = sum & 0xFFFF;
    return sum;

}

void rev( void *start, int size )
{
    unsigned char *lo = start;
    unsigned char *hi = start + size - 1;
    unsigned char swap;
    while (lo < hi) {
        swap = *lo;
        *lo++ = *hi;
        *hi-- = swap;
    }
}
void tcpcsum(struct iphdr *pIph, unsigned short *ipPayload) {

    register unsigned long sum = 0;

    unsigned short tcpLen = ntohs(pIph->tot_len) - (pIph->ihl<<2);

    struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);

    //add the pseudo header 

    //the source ip

    sum += (pIph->saddr>>16)&0xFFFF;

    sum += (pIph->saddr)&0xFFFF;

    //the dest ip

    sum += (pIph->daddr>>16)&0xFFFF;

    sum += (pIph->daddr)&0xFFFF;

    //protocol and reserved: 6

    sum += htons(IPPROTO_TCP);

    //the length

    sum += htons(tcpLen);



    //add the IP payload

    //initialize checksum to 0

    tcphdrp->check = 0;

    while (tcpLen > 1) {

        sum += * ipPayload++;

        tcpLen -= 2;

    }

    //if any bytes left, pad the bytes and add

    if(tcpLen > 0) {

        //printf("+++++++++++padding, %dn", tcpLen);

        sum += ((*ipPayload)&htons(0xFF00));

    }

    //Fold 32-bit sum to 16 bits: add carrier to result

    while (sum>>16) {

        sum = (sum & 0xffff) + (sum >> 16);

    }

    sum = ~sum;

    //set computation result

    tcphdrp->check = (unsigned short)sum;

}

/* *
 * Modifies handshake packets in attack mode.
 * TODO: Replace hardcoded IP addresses with live encryption and dynamically chosen helping servers
 * TODO: Handle ACK handshake packets
 * */
static void modify_handshk_pkt(full_tcp_pkt_t *pkt, int pkt_len) {

    /* Should match only SYN packets */
    printf("\nPacket intercepted: \n");
    if (pkt->tcp_header.syn == 1 && pkt->tcp_header.ack == 0) {
        printf("\tPacket type: SYN\n");
        pkt_meta *metadata =
            (pkt_meta *)((unsigned char *)pkt + sizeof(pkt->ipv4_header) + sizeof(pkt->tcp_header));
        char fname[metadata->exp_opt_len];
        strncpy(fname, (const char *)metadata + 4, metadata->exp_opt_len - 4);

        printf("%s", fname);
    }


}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    u_int32_t id;

    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);
    id = ntohl(ph->packet_id);
    printf("entering callback\n");

    full_tcp_pkt_t *ipv4_payload = NULL;
    int pkt_len = nfq_get_payload(nfa, (unsigned char **) &ipv4_payload);
    modify_handshk_pkt(ipv4_payload, pkt_len);

    rev(&ipv4_payload->ipv4_header.tot_len, 2);
    ipv4_payload->ipv4_header.tot_len += METADATA_SIZE;
    rev(&ipv4_payload->ipv4_header.tot_len, 2);

	ipv4_payload->ipv4_header.check = 0;
    ipv4_payload->ipv4_header.check =
        ipcsum((unsigned char *)&ipv4_payload->ipv4_header,
                20);
    rev(&ipv4_payload->ipv4_header.check, 2); // Convert between endians

    tcpcsum(&ipv4_payload->ipv4_header,
          (unsigned short *)&ipv4_payload->tcp_header);
    int ret = nfq_set_verdict(qh, id, NF_ACCEPT, (u_int32_t) pkt_len,
            (void *) ipv4_payload);
    printf("\n Set verdict status: %s\n", strerror(errno));
    return ret;
}

uint16_t running_csum(addr_t old_src, addr_t new_src, uint16_t old_checksum) {
    return ~(~old_checksum + ~old_src + (new_src));
}

int main(int argc, char **argv) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    file_info_hash *files = NULL;
    file_info_hash *test = malloc(sizeof(file_info_hash));
    test->buf = malloc(4);
    strncpy(test->buf, "test", 4);
    test->buf_len = 4;
    test->key.ip_addr = 4;
    test->key.dst_port = 80;
    HASH_ADD(hh, files, key, sizeof(hash_key), test);
    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h, 0, &cb, files);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    // para el tema del loss:   while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)

    while ((rv = recv(fd, buf, sizeof(buf), 0))) {
        printf("pkt received\n");
        nfq_handle_packet(h, buf, rv);
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
