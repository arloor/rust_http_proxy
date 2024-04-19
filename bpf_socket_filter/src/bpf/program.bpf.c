#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// copy from #include <linux/if_ether.h>
#define ETH_HLEN	14		/* Total octets in header.	 */
// copy from  <linux/if_packet.h>
#define PACKET_OUTGOING		4		/* Outgoing of any type */

#define IP_PROTO_OFF offsetof(struct iphdr, protocol)
#define IP_DEST_OFF offsetof(struct iphdr, daddr)

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} map SEC(".maps");

/*
 * Track size of outgoing ICMP and UDP packets
 */
SEC("socket")
int bpf_program(struct __sk_buff *skb) {
    // Only outgoing packets
    if (skb->pkt_type != PACKET_OUTGOING) return 0;

    __u32 proto = IPPROTO_IP;
    // __u32 dest = 0;

    // Only ICMP and UDP packets
    // bpf_skb_load_bytes(skb, ETH_HLEN + IP_PROTO_OFF, &proto, 1);
    // if (proto != IPPROTO_ICMP && proto != IPPROTO_UDP) return 0;

    // // Only localhost destination
    // bpf_skb_load_bytes(skb, ETH_HLEN + IP_DEST_OFF, &dest, sizeof(dest));
    // if (ntohl(dest) != 0x7f000001) return 0;

    long *value = bpf_map_lookup_elem(&map, &proto);
    if (value) {
        __sync_fetch_and_add(value, skb->len);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
