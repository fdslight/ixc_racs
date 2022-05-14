#include<arpa/inet.h>
#include<string.h>
#include<time.h>
#include<stdlib.h>

#include "ip.h"
#include "ipv6.h"
#include "racs.h"
#include "dnat.h"
#include "qos.h"

#include "../../../pywind/clib/debug.h"
#include "../../../pywind/clib/netutils.h"


void ip_handle(struct mbuf *m)
{
    struct netutil_iphdr *header=(struct netutil_iphdr *)(m->data+m->offset);
    int version= (header->ver_and_ihl & 0xf0) >> 4;
    int tot_len=ntohs(header->tot_len);
    int hdr_len=0;
    unsigned char ip_unspec[]={0x00,0x00,0x00,0x00};

    
    // 限制数据包最大长度
    if(m->tail-m->offset>1500){
        mbuf_put(m);
        return;
    }
    
    // 检查是否是IPv6,如果是IPv6那么处理IPv6协议
    if(version==6){
        ipv6_handle(m);
        return;
    }

    hdr_len=(header->ver_and_ihl & 0x0f) * 4;

    // 首先检查长度是否符合要求
    if(m->tail-m->offset!=tot_len){
        //DBG_FLAGS;
        mbuf_put(m);
        return;
    }

    // 不能存在空的数据包
    if(hdr_len==tot_len){
        mbuf_put(m);
        return;
    }

    if(!memcmp(header->dst_addr,ip_unspec,4)){
        mbuf_put(m);
        return;
    }

    if(header->dst_addr[0]==127 || header->dst_addr[0]==255){
        mbuf_put(m);
        return;
    }

    if(header->dst_addr[0]>=224 && header->dst_addr[0]<=239){
        mbuf_put(m);
        return;
    }

    // 源地址和目的地址不能一样
    if(!memcmp(header->src_addr,header->dst_addr,4)){
        mbuf_put(m);
        return;
    }

    m->is_ipv6=0;

    ixc_dnat_handle(m,header);

}