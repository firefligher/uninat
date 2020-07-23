#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>

#include "queue_worker.h"
#include "mapping.h"

struct __worker_callback_data {
    struct uninat_table **table_ptr;
    enum uninat_cmdline_mode execution_mode;
    int verbose;
};

static int __worker_callback(
    struct nfq_q_handle *qh,
    struct nfgenmsg *nfmsg,
    struct nfq_data *nfad,
    void *data);

static void __format_ipv4_addr_be(
    char *dst,
    uint32_t addr_be,
    size_t dst_length);

/**
 * This is the size of the buffer that will be used for the copied packet
 * data.
 *
 * Since NAT requires the recalculation of multiple checksums, including those
 * of TCP and UDP (and we need the whole packet for this operation), this size
 * also defines the maximum size of any translated packet.
 */
#define COPY_BUFFER_SIZE        1500

/* The maximum length of an IPv4 address */
#define IPV4_ADDR_MAX_LENGTH    15

int uninat_queue_worker_initialize(
    struct uninat_queue_worker *wkr,
    int queue_number,
    struct uninat_table **table_ptr,
    enum uninat_cmdline_mode execution_mode,
    int verbose) {
    struct __worker_callback_data *wkr_data;

    /*
     * Resetting the passed worker instance, preparing the callback data and
     * allocating memory for the packet buffer.
     */

    memset(wkr, 0, sizeof(struct uninat_queue_worker));

    wkr_data = calloc(1, sizeof(struct __worker_callback_data));

    if (wkr_data == NULL) {
        fprintf(stderr, "err:\tFailed allocating memory!\n");
        return 0;
    }

    wkr->__worker_data = (void *)wkr_data;
    wkr->__flags |= UNINAT_QUEUE_WORKER_FLAG_WORKER_DATA_INITIALIZED;

    wkr_data->table_ptr = table_ptr;
    wkr_data->execution_mode = execution_mode;
    wkr_data->verbose = verbose;
    
    wkr->__packet_buffer = malloc(COPY_BUFFER_SIZE);

    if (wkr->__packet_buffer == NULL) {
        fprintf(stderr, "err:\tFailed allocating memory!\n");
        free(wkr_data);
        wkr->__flags &= ~UNINAT_QUEUE_WORKER_FLAG_WORKER_DATA_INITIALIZED;
        return 0;
    }

    wkr->__flags |= UNINAT_QUEUE_WORKER_FLAG_PACKET_BUFFER_INITIALIZED;

    /*
     * Establishing a connection to netfilter module inside the Linux kernel.
     */

    wkr->nfq_handle = nfq_open();

    if (wkr->nfq_handle == NULL) {
        fprintf(stderr, "err:\tFailed establishing connection to NFQ!\n");

        free(wkr_data);
        free(wkr->__packet_buffer);

        wkr->__flags &= ~(
            UNINAT_QUEUE_WORKER_FLAG_WORKER_DATA_INITIALIZED |
            UNINAT_QUEUE_WORKER_FLAG_PACKET_BUFFER_INITIALIZED);
        
        return 0;
    }

    wkr->__flags |= UNINAT_QUEUE_WORKER_FLAG_NFQ_HANDLE_INITIALIZED;

    /* NOTE: Calling nfq_bind_pf is ignored on Linux 3.8+ */

    if (nfq_bind_pf(wkr->nfq_handle, PF_INET) < 0) {
        fprintf(stderr, "err:\tFailed binding NFQ handle to PF_INET!\n");

        free(wkr_data);
        free(wkr->__packet_buffer);
        nfq_close(wkr->nfq_handle);

        wkr->__flags &= ~(
            UNINAT_QUEUE_WORKER_FLAG_WORKER_DATA_INITIALIZED |
            UNINAT_QUEUE_WORKER_FLAG_PACKET_BUFFER_INITIALIZED |
            UNINAT_QUEUE_WORKER_FLAG_NFQ_HANDLE_INITIALIZED);
        
        return 0;
    }

    /*
     * Creating a handle for the queue that has been specified as
     * queue_number.
     */

    wkr->queue_handle = nfq_create_queue(
        wkr->nfq_handle,
        queue_number,
        &__worker_callback,
        wkr_data);

    if (wkr->queue_handle == NULL) {
        fprintf(
            stderr,
            "err:\tFailed creation NFQ queue with queue number %d!\n",
            queue_number);

        free(wkr_data);
        free(wkr->__packet_buffer);
        nfq_close(wkr->nfq_handle);

        wkr->__flags &= ~(
            UNINAT_QUEUE_WORKER_FLAG_WORKER_DATA_INITIALIZED |
            UNINAT_QUEUE_WORKER_FLAG_PACKET_BUFFER_INITIALIZED |
            UNINAT_QUEUE_WORKER_FLAG_NFQ_HANDLE_INITIALIZED);

        return 0;
    }

    wkr->__flags |= UNINAT_QUEUE_WORKER_FLAG_QUEUE_HANDLE_INITIALIZED;

    if (nfq_set_mode(
        wkr->queue_handle,
        NFQNL_COPY_PACKET,
        COPY_BUFFER_SIZE) == -1) {
        fprintf(stderr, "err:\tFailed setting NFQ mode!\n");

        free(wkr_data);
        free(wkr->__packet_buffer);
        nfq_destroy_queue(wkr->queue_handle);
        nfq_close(wkr->nfq_handle);

        wkr->__flags &= ~(
            UNINAT_QUEUE_WORKER_FLAG_WORKER_DATA_INITIALIZED |
            UNINAT_QUEUE_WORKER_FLAG_PACKET_BUFFER_INITIALIZED |
            UNINAT_QUEUE_WORKER_FLAG_NFQ_HANDLE_INITIALIZED |
            UNINAT_QUEUE_WORKER_FLAG_QUEUE_HANDLE_INITIALIZED);

        return 0;
    }

    wkr->nfq_fd = nfq_fd(wkr->nfq_handle);
    wkr->__flags |= UNINAT_QUEUE_WORKER_FLAG_NFQ_FD_INITIALIZED;

    return 1;
}

void uninat_queue_worker_cleanup(struct uninat_queue_worker *wkr) {
    if (wkr->__flags & UNINAT_QUEUE_WORKER_FLAG_NFQ_FD_INITIALIZED) {
        close(wkr->nfq_fd);
        wkr->__flags &= ~UNINAT_QUEUE_WORKER_FLAG_NFQ_FD_INITIALIZED;
    }

    if (wkr->__flags & UNINAT_QUEUE_WORKER_FLAG_QUEUE_HANDLE_INITIALIZED) {
        nfq_destroy_queue(wkr->queue_handle);
        wkr->__flags &= ~UNINAT_QUEUE_WORKER_FLAG_QUEUE_HANDLE_INITIALIZED;
    }

    if (wkr->__flags & UNINAT_QUEUE_WORKER_FLAG_NFQ_HANDLE_INITIALIZED) {
        nfq_close(wkr->nfq_handle);
        wkr->__flags &= ~UNINAT_QUEUE_WORKER_FLAG_NFQ_HANDLE_INITIALIZED;
    }

    if (wkr->__flags & UNINAT_QUEUE_WORKER_FLAG_WORKER_DATA_INITIALIZED) {
        free(wkr->__worker_data);
        wkr->__flags &= ~UNINAT_QUEUE_WORKER_FLAG_WORKER_DATA_INITIALIZED;
    }

    if (wkr->__flags & UNINAT_QUEUE_WORKER_FLAG_PACKET_BUFFER_INITIALIZED) {
        free(wkr->__packet_buffer);
        wkr->__flags &= ~UNINAT_QUEUE_WORKER_FLAG_PACKET_BUFFER_INITIALIZED;
    }
}

int uninat_queue_worker_process(struct uninat_queue_worker *wkr) {
    ssize_t len;

    /* Receive some bytes. */

    len = recv(wkr->nfq_fd, wkr->__packet_buffer, COPY_BUFFER_SIZE, 0);

    if (len == -1) {
        fprintf(stderr, "err:\tFailed receiving data from NFQ!\n");
        return 0;
    }

    if (nfq_handle_packet(
        wkr->nfq_handle,
        wkr->__packet_buffer,
        (int)len) != 0) {
        fprintf(stderr, "err:\tFailed handling packet!\n");
        return 0;
    }

    return 1;
}

static int __worker_callback(
    struct nfq_q_handle *qh,
    struct nfgenmsg *nfmsg,
    struct nfq_data *nfad,
    void *data) {
    int payload_len;
    uint32_t pkt_id, check_addr;
    size_t mapping_idx;
    char ipv4_addr[IPV4_ADDR_MAX_LENGTH + 1];
    char *payload;
    uninat_mapping *mapping;
    struct nfqnl_msg_packet_hdr *pkt_hdr;
    struct iphdr *ip_hdr;
    struct __worker_callback_data *wkr_data;

    wkr_data = (struct __worker_callback_data *)data;

    /*
     * We need to extract the packet id and the payload length to be able to
     * accept or discard the packet later on.
     *
     * Also, we want to get the payload data which contains the IPv4 header
     * structure that we are interested in.
     */

    pkt_hdr = nfq_get_msg_packet_hdr(nfad);
    pkt_id = ntohl(pkt_hdr->packet_id);
    payload_len = nfq_get_payload(nfad, (unsigned char **)&payload);

    if (payload_len == -1) {
        fprintf(
            stderr,
            "warn:\tFailed retrieving payload of packet %d, dropping.\n",
            pkt_id);

        return nfq_set_verdict(
            qh,
            pkt_id,
            NF_DROP,
            payload_len,
            (const unsigned char *)payload);
    }

    /*
     * Modifying the IPv4 header depending on the execution mode and the
     * current mapping table.
     */

    ip_hdr = (struct iphdr *)payload;

    if (wkr_data->verbose) {
        char src_addr[IPV4_ADDR_MAX_LENGTH + 1],
            dst_addr[IPV4_ADDR_MAX_LENGTH + 1];

        __format_ipv4_addr_be(
            src_addr,
            ip_hdr->saddr,
            IPV4_ADDR_MAX_LENGTH + 1);

        __format_ipv4_addr_be(
            dst_addr,
            ip_hdr->daddr,
            IPV4_ADDR_MAX_LENGTH + 1);

        fprintf(
            stderr,
            "info:\tReceived packet %d [SRC: %s, DST: %s]\n",
            pkt_id,
            src_addr,
            dst_addr);
    }

    switch (wkr_data->execution_mode) {
    case UNINAT_CMDLINE_MODE_PREROUTING:
        check_addr = ip_hdr->saddr;
        break;

    case UNINAT_CMDLINE_MODE_POSTROUTING:
        check_addr = ip_hdr->daddr;
        break;

    default:
        fprintf(
            stderr,
            "err:\tInvalid execution mode, dropping packet %d!\n",
            pkt_id);

        nfq_set_verdict(
            qh,
            pkt_id,
            NF_DROP,
            payload_len,
            (const unsigned char *)payload);

        return -1;
    }

    /* Looking for a table entry that matches. */

    for (mapping_idx = 0;
        mapping_idx < (*wkr_data->table_ptr)->entry_count;
        mapping_idx++) {
        void *layerIII_payload;
        struct tcphdr *tcp_hdr;
        struct udphdr *udp_hdr;

        /* Getting a pointer to the current mapping instance */

        mapping = &(*wkr_data->table_ptr)->entries[mapping_idx];

        /* Testing, if the mapping applies for the check_addr */

        if ((check_addr & mapping->original_mask) !=
            (mapping->original_addr & mapping->original_mask)) {
            continue;
        }

        /*
         * Performing the replacement on both, source and destination address.
         */

        ip_hdr->saddr =
            (mapping->replacement_addr & mapping->replacement_mask) |
            (ip_hdr->saddr & ~mapping->replacement_mask);

        ip_hdr->daddr =
            (mapping->replacement_addr & mapping->replacement_mask) |
            (ip_hdr->daddr & ~mapping->replacement_mask);

        /* Verbose logging */

        if (wkr_data->verbose) {
            char src_addr[IPV4_ADDR_MAX_LENGTH + 1],
                dst_addr[IPV4_ADDR_MAX_LENGTH + 1];

            __format_ipv4_addr_be(
                src_addr,
                ip_hdr->saddr,
                IPV4_ADDR_MAX_LENGTH + 1);

            __format_ipv4_addr_be(
                dst_addr,
                ip_hdr->daddr,
                IPV4_ADDR_MAX_LENGTH + 1);

            fprintf(
                stderr,
                "info:\tAdjusted packet %d [SRC: %s, DST: %s]\n",
                pkt_id,
                src_addr,
                dst_addr);
        }

        /*
         * Since we modified the IPv4 header, we need to update the its
         * checksum.
         */

        nfq_ip_set_checksum(ip_hdr);

        /**
         * Also, depending on the ISO/OSI Layer IV protocol, we need to update
         * the protocol-specific checksum (only, if it depends on the contents
         * of the IPv4 header).
         *
         * At the moment the following protocols are supported and handled
         * correctly:
         *  - ICMPv4
         *  - TCP
         *  - UDP
         *  - Any other Layer IV protocol whose transfered information does not
         *    depend on the IPv4 header at all (requires whitelisting in the
         *    following switch-case-construction).
         *
         * (A list of common and partially exotic protocols can be found here:
         *  https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers, offical
         *  page: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
         *
         */

        layerIII_payload = (void *)(payload + ip_hdr->ihl * 4);

        switch (ip_hdr->protocol) {
        case IPPROTO_ICMP:
            /*
             * Good news: ICMPv4 does not require any further modification of
             *            the payload since its checksum is calculated
             *            independently of the IPv4 header.
             */
            break;

        case IPPROTO_TCP:
            tcp_hdr = (struct tcphdr *)layerIII_payload;

            if (wkr_data->verbose) {
                fprintf(
                    stderr,
                    "info:\tPacket %d is TCP, checksum: %d\n",
                    pkt_id,
                    ntohl(tcp_hdr->check));
            }

            nfq_tcp_compute_checksum_ipv4(tcp_hdr, ip_hdr);

            if (wkr_data->verbose) {
                fprintf(
                    stderr,
                    "info:\tUpdated TCP checksum of packet %d: %d\n",
                    pkt_id,
                    ntohl(tcp_hdr->check));
            }

            break;

        case IPPROTO_UDP:
            udp_hdr = (struct udphdr *)layerIII_payload;

            if (wkr_data->verbose) {
                fprintf(
                    stderr,
                    "info:\tPacket %d is UDP, checksum: %d\n",
                    pkt_id,
                    ntohl(udp_hdr->check));
            }

            /*nfq_udp_compute_checksum_ipv4(udp_hdr, ip_hdr);*/

            if (wkr_data->verbose) {
                fprintf(
                    stderr,
                    "info:\tUpdated UDP checksum of packet %d: %d\n",
                    pkt_id,
                    ntohl(udp_hdr->check));
            }

            break;

        default:
            fprintf(
                stderr,
                "warn:\tUnsupported Layer IV protocol with id: %d, dropping "
                    "packet %d!\n",
                ip_hdr->protocol,
                pkt_id);

            return nfq_set_verdict(
                qh,
                pkt_id,
                NF_DROP,
                payload_len,
                (const unsigned char *)payload);
        }

        /* Finally, accepting the packet. */

        return nfq_set_verdict(
            qh,
            pkt_id,
            NF_ACCEPT,
            payload_len,
            (const unsigned char *)payload);
    }

    /*
     * NOTE: Returning a value bellow zero will prevent the queue from further
     *       processing.
     */

    __format_ipv4_addr_be(ipv4_addr, check_addr, IPV4_ADDR_MAX_LENGTH + 1);

    fprintf(
        stderr,
        "warn:\tNo matching entry found for address: %s, dropping packet "
            "%d!\n",
        ipv4_addr,
        pkt_id);

    return nfq_set_verdict(
        qh,
        pkt_id,
        NF_DROP,
        payload_len,
        (const unsigned char *)payload);
}

static void __format_ipv4_addr_be(
    char *dst,
    uint32_t addr_be,
    size_t dst_length) {
    memset(dst, 0, dst_length);

    snprintf(
        dst,
        dst_length,
        "%u.%u.%u.%u",
        ((unsigned char *)&addr_be)[0],
        ((unsigned char *)&addr_be)[1],
        ((unsigned char *)&addr_be)[2],
        ((unsigned char *)&addr_be)[3]);
}
