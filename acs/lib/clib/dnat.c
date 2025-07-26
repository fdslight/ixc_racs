#include<string.h>
#include<stdlib.h>


#include "dnat.h"
#include "qos.h"
#include "racs.h"
#include "debug.h"

#include "../../../pywind/clib/netutils.h"
#include "../../../pywind/clib/debug.h"

static struct ixc_dnat dnat;

static void ixc_dnat_del_cb(void *data)
{
    struct ixc_dnat_rule *rule=data;
    rule->refcnt-=1;

    if(0==rule->refcnt) free(rule);
}

int ixc_dnat_init(void)
{
    struct map *m=NULL;
    int rs;
    bzero(&dnat,sizeof(struct ixc_dnat));
    
    rs=map_new(&m,4);
    if(rs<0){
        STDERR("cannot create map\r\n");
        return -1;
    }
    dnat.left2right=m;
    rs=map_new(&m,20);
    if(rs<0){
        ixc_dnat_uninit();
        STDERR("cannot create map\r\n");
        return -1;
    }
    dnat.right2left=m;

    rs=map_new(&m,16);
    if(rs<0){
        ixc_dnat_uninit();
        STDERR("cannot create map\r\n");
        return -1;
    }
    dnat.left2right_v6=m;
    rs=map_new(&m,32);
    if(rs<0){
        ixc_dnat_uninit();
        STDERR("cannot create map\r\n");
        return -1;
    }
    dnat.right2left_v6=m;


    return 0;
}

void ixc_dnat_uninit(void)
{
    if(NULL!=dnat.left2right) map_release(dnat.left2right,ixc_dnat_del_cb);
    if(NULL!=dnat.right2left) map_release(dnat.right2left,ixc_dnat_del_cb);
    if(NULL!=dnat.left2right_v6) map_release(dnat.left2right_v6,ixc_dnat_del_cb);
    if(NULL!=dnat.right2left_v6) map_release(dnat.right2left_v6,ixc_dnat_del_cb);

    return;
}

static void ixc_dnat_tcp_mss_modify(struct netutil_tcphdr *tcp_header,int is_ipv6)
{
    unsigned short csum=ntohs(tcp_header->csum);
    unsigned char *ptr=(unsigned char *)tcp_header;
    unsigned short header_len_and_flag=ntohs(tcp_header->header_len_and_flag);
    int header_size=((header_len_and_flag & 0xf000) >> 12) * 4;
    int is_syn= (header_len_and_flag & 0x0002) >> 1;
    unsigned short tcp_mss=0,set_tcp_mss;
    unsigned char *tcp_opt=ptr+20;
    unsigned short *tcp_mss_ptr=NULL;
    unsigned char x,length;

    // 检查是否是SYN报文
    //DBG_FLAGS;
    if(!is_syn) return;
    //DBG_FLAGS;
    if(header_size<=20) return;

    //DBG_FLAGS;
    for(int n=0;n<header_size-20;){
        x=*tcp_opt++;
        if(0==x) break;
        if(1==x) {
            n+=1;
            continue;
        }
        length=*tcp_opt++;
        if(2==x){
            if(4==length) {
                tcp_mss_ptr=(unsigned short *)(tcp_opt);
                memcpy(&tcp_mss,tcp_opt,2);
            }
            break;
       } 
       tcp_opt=tcp_opt+length-2;
       n+=length;
    }

    if(0==tcp_mss) return;
  
    tcp_mss=ntohs(tcp_mss);
    //DBG("tcp mss %d set tcp mss %d\r\n",tcp_mss,set_tcp_mss);
    
    if(is_ipv6) set_tcp_mss=dnat.tcp_mss_v6;
    else set_tcp_mss=dnat.tcp_mss_v4;

    // 实际TCP MSS小于设置值,那么不修改
    if(tcp_mss<=set_tcp_mss) return;
    //DBG_FLAGS;
    *tcp_mss_ptr=htons(set_tcp_mss);
    csum=csum_calc_incre(tcp_mss,set_tcp_mss,csum);
    tcp_header->csum=htons(csum);

}

static void ixc_dnat_modify_ip_tcp_mss(struct netutil_iphdr *header)
{
    int header_size= (header->ver_and_ihl & 0x0f) * 4;
    unsigned char *ptr=(unsigned char *)header;
    struct netutil_tcphdr *tcp_header=NULL;

    if(0==dnat.tcp_mss_v4) return;
    if(6!=header->protocol) return;

    ptr=ptr+header_size;

    tcp_header=(struct netutil_tcphdr *)ptr;
    ixc_dnat_tcp_mss_modify(tcp_header,0);
}

static void ixc_dnat_modify_ip6_tcp_mss(struct netutil_ip6hdr *header)
{
    unsigned char *ptr=(unsigned char *)header;
    struct netutil_tcphdr *tcp_header=NULL;

    if(0==dnat.tcp_mss_v6) return;
    if(6!=header->next_header) return;

    ptr=ptr+40;
    tcp_header=(struct netutil_tcphdr *)ptr;
    ixc_dnat_tcp_mss_modify(tcp_header,1);
}

static void ixc_dnat_rewrite_for_icmpv6(struct mbuf *m,unsigned char *new_addr,int is_src)
{
    struct netutil_icmpv6hdr *icmpv6hdr=(struct netutil_icmpv6hdr *)(m->data+m->offset+40);
    struct netutil_ip6hdr *header=NULL;
    unsigned char *ptr=m->data+m->offset+48;
    int need_handle_flags=0;

    switch(icmpv6hdr->type){
        case 1:
        case 2:
        case 3:
        case 4:
            need_handle_flags=1;
            break;
        default:
            need_handle_flags=0;
            break;
    }
    // 只处理错误消息
    if(!need_handle_flags) return;
    // 重写错误消息内部的IPv6数据包
    header=(struct netutil_ip6hdr *)ptr;

    // 这里IPv6内部原始数据包需要反过来,因为是发送流量或者接收流量的复制
    if(is_src){
        rewrite_ip6_addr(header,new_addr,0);
    }else{
        rewrite_ip6_addr(header,new_addr,1);
    }
}

static void ixc_dnat_handle_v6(struct mbuf *m,struct netutil_ip6hdr *header)
{
    struct map *map;
    unsigned char key[32];
    char is_found;
    struct ixc_dnat_rule *rule;
    
    if(m->from==MBUF_FROM_WAN){
        if(!memcmp(header->src_addr,dnat.local_old_ip6,16)) rewrite_ip6_addr(header,dnat.local_new_ip6,1);

        map=dnat.left2right_v6;
        memcpy(key,header->dst_addr,16);
    }else{
        if(!memcmp(header->dst_addr,dnat.local_new_ip6,16)) rewrite_ip6_addr(header,dnat.local_old_ip6,0);

        map=dnat.right2left_v6;
        memcpy(key,m->id,16);
        memcpy(key+16,header->dst_addr,16);
    }

    rule=map_find(map,(char *)key,&is_found);
    if(NULL==rule){
        mbuf_put(m);
        return;
    }

    memcpy(m->id,rule->id,16);

    ixc_dnat_modify_ip6_tcp_mss(header);

    if(m->from==MBUF_FROM_WAN) {
        rewrite_ip6_addr(header,rule->right_addr,0);
        ixc_dnat_rewrite_for_icmpv6(m,rule->right_addr,0);
        qos_add(m);
    }else{
        rewrite_ip6_addr(header,rule->left_addr,1);
        ixc_dnat_rewrite_for_icmpv6(m,rule->left_addr,1);
        netpkt_send(m);
    }
}

static void ixc_dnat_rewrite_for_icmp(struct mbuf *m,struct netutil_iphdr *iphdr,unsigned char *new_addr,int is_src)
{
    int hdr_len=(iphdr->ver_and_ihl & 0x0f) * 4;
    int need_handle_flags;
    struct netutil_icmphdr *icmphdr=(struct netutil_icmphdr *)(m->data+m->offset+hdr_len);

    switch(icmphdr->type){
        case 3:
        case 4:
        case 11:
        case 12:
            need_handle_flags=1;
            break;
        default:
            need_handle_flags=0;
            break;
    }

    if(!need_handle_flags) return;
    iphdr=(struct netutil_iphdr *)(m->data+m->offset+hdr_len+8);
    // 这里因为是原始数据包,所以方向需要反过来
    if(is_src){
        rewrite_ip_addr(iphdr,new_addr,0);
    }else{
        rewrite_ip_addr(iphdr,new_addr,1);
    }
}

static void ixc_dnat_handle_v4(struct mbuf *m,struct netutil_iphdr *header)
{
    struct map *map;
    unsigned char key[20];
    char is_found;
    struct ixc_dnat_rule *rule;

    if(m->from==MBUF_FROM_WAN){
        // 如果是本机地址,那么重写本机地址
        if(!memcmp(header->src_addr,dnat.local_old_ip,4)) rewrite_ip_addr(header,dnat.local_new_ip,1);

        map=dnat.left2right;
        memcpy(key,header->dst_addr,4);
    }else{
        // 如果是本机地址,那么重写本机地址
        if(!memcmp(header->dst_addr,dnat.local_new_ip,4)) rewrite_ip_addr(header,dnat.local_old_ip,0);

        map=dnat.right2left;
        memcpy(key,m->id,16);
        memcpy(key+16,header->src_addr,4);
    }

    rule=map_find(map,(char *)key,&is_found);
    if(NULL==rule){
        mbuf_put(m);
        return;
    }

    memcpy(m->id,rule->id,16);

    ixc_dnat_modify_ip_tcp_mss(header);
    
    if(m->from==MBUF_FROM_WAN){
        rewrite_ip_addr(header,rule->right_addr,0);
        ixc_dnat_rewrite_for_icmp(m,header,rule->right_addr,0);
        qos_add(m);
    }else{
        rewrite_ip_addr(header,rule->left_addr,1);
        ixc_dnat_rewrite_for_icmp(m,header,rule->left_addr,1);
        netpkt_send(m);
    }
}

void ixc_dnat_handle(struct mbuf *m,void *ip_header)
{
    if(m->is_ipv6) ixc_dnat_handle_v6(m,ip_header);
    else ixc_dnat_handle_v4(m,ip_header);
}

int ixc_dnat_rule_add(const unsigned char *_id,const unsigned char *left_addr,const unsigned char *right_addr,int is_ipv6)
{
    struct map *left2right_m;
    struct map *right2left_m;
    struct ixc_dnat_rule *rule;
    unsigned char key_left2right[32];
    unsigned char key_right2left[32];
    int rs;
    char is_found;

    if(is_ipv6){
        left2right_m=dnat.left2right_v6;
        right2left_m=dnat.right2left_v6;

        memcpy(key_left2right,left_addr,16);
        memcpy(key_right2left,_id,16);
        memcpy(key_right2left+16,right_addr,16);

    }else{
        left2right_m=dnat.left2right;
        right2left_m=dnat.right2left;

        memcpy(key_left2right,left_addr,4);
        memcpy(key_right2left,_id,16);
        memcpy(key_right2left+16,right_addr,4);
    }

    // 检查规则是否存在
    rule=map_find(left2right_m,(char *)key_left2right,&is_found);
    if(NULL!=rule){
        STDERR("rule exists\r\n");
        return -1;
    }

    rule=malloc(sizeof(struct ixc_dnat_rule));
    if(NULL==rule){
        STDERR("cannot malloc struct ixc_dnat_rule\r\n");
        return -1;
    }

    bzero(rule,sizeof(struct ixc_dnat_rule));

    rs=map_add(left2right_m,(char *)key_left2right,rule);
    if(rs<0){
        free(rule);
        STDERR("cannot add to rule\r\n");
        return -1;
    }
    rs=map_add(right2left_m,(char *)key_right2left,rule);
    if(rs<0){
        free(rule);
        map_del(left2right_m,(char *)key_left2right,NULL);
        STDERR("cannot add to rule\r\n");
        return -1;
    }

    rule->is_ipv6=is_ipv6;
    memcpy(rule->id,_id,16);
    if(is_ipv6){
        memcpy(rule->left_addr,left_addr,16);
        memcpy(rule->right_addr,right_addr,16);
    }else{
        memcpy(rule->left_addr,left_addr,4);
        memcpy(rule->right_addr,right_addr,4);
    }

    rule->refcnt=2;

    return 0;
}

void ixc_dnat_rule_del(unsigned char *left_addr,int is_ipv6)
{
    struct map *left2right_m;
    struct map *right2left_m;
    struct ixc_dnat_rule *rule;
    unsigned char key[32];
    char is_found;

    if(is_ipv6){
        left2right_m=dnat.left2right_v6;
        right2left_m=dnat.right2left_v6;
        memcpy(key+16,left_addr,16);
    }else{
        left2right_m=dnat.left2right;
        right2left_m=dnat.right2left;
        memcpy(key+16,left_addr,4);
    }

    rule=map_find(left2right_m,(char *)left_addr,&is_found);
    if(NULL==rule) return;

    memcpy(key,rule->id,16);

    map_del(left2right_m,(char *)left_addr,ixc_dnat_del_cb);
    map_del(right2left_m,(char *)key,ixc_dnat_del_cb);
}

int ixc_dnat_local_rule_set(const unsigned char *old_addr,const unsigned char *new_addr,int is_ipv6)
{
    if(is_ipv6){
        memcpy(dnat.local_old_ip6,old_addr,16);
        memcpy(dnat.local_new_ip6,new_addr,16);
    }else{
        memcpy(dnat.local_old_ip,old_addr,4);
        memcpy(dnat.local_new_ip,new_addr,4);
    }

    return 0;
}

int ixc_dnat_tcp_mss_set(unsigned int mss,int is_ipv6)
{
    if(mss>1500) {
        STDERR("wrong tcp mss value size %u\r\n",mss);
        return -1;
    }

    if(is_ipv6){
        if(mss>0 && mss < 516){
            STDERR("wrong tcp mss value size %u for ipv6\r\n",mss);
            return -1;
        }
    }else{
        if(mss>0 && mss<536){
            STDERR("wrong tcp mss value size %u for ipv4\r\n",mss);
            return -1;
        }
    }
    
    if(is_ipv6) dnat.tcp_mss_v6=mss;
    else dnat.tcp_mss_v4=mss;

    return 0;
}