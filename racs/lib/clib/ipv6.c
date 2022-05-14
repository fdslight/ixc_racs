#include<string.h>
#include<arpa/inet.h>
#include<time.h>

#include "ipv6.h"
#include "dnat.h"
#include "qos.h"
#include "debug.h"

#include "../../../pywind/clib/debug.h"
#include "../../../pywind/clib/netutils.h"

void ipv6_handle(struct mbuf *m)
{
    struct netutil_ip6hdr *header;
    int payload_len=0;

    if(m->tail-m->offset<41){
        mbuf_put(m);
        return;
    }

    m->is_ipv6=1;
    header=(struct netutil_ip6hdr *)(m->data+m->offset);

    payload_len=ntohs(header->payload_len);
    if(m->tail-m->offset!=(payload_len+40)){
        mbuf_put(m);
        return;
    }

    if(header->dst_addr[0]==0){
        mbuf_put(m);
        return;
    }

    // 源地址和目标地址不能一样
    if(!memcmp(header->src_addr,header->dst_addr,16)){
        mbuf_put(m);
        return;
    }

    ixc_dnat_handle(m,header);

}