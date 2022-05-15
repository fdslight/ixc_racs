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

static void ixc_dnat_handle_v6(struct mbuf *m,struct netutil_ip6hdr *header)
{
    struct map *map;
    unsigned char key[32];
    char is_found;
    struct ixc_dnat_rule *rule;
    
    if(m->from==MBUF_FROM_WAN){
        map=dnat.left2right_v6;
        memcpy(key,header->dst_addr,16);
    }else{
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

    if(m->from==MBUF_FROM_WAN) {
        rewrite_ip6_addr(header,rule->right_addr,0);
        qos_add(m);
    }else{
        rewrite_ip6_addr(header,rule->left_addr,1);
        netpkt_send(m);
    }
}

static void ixc_dnat_handle_v4(struct mbuf *m,struct netutil_iphdr *header)
{
    struct map *map;
    unsigned char key[20];
    char is_found;
    struct ixc_dnat_rule *rule;
    
    if(m->from==MBUF_FROM_WAN){
        map=dnat.left2right;
        memcpy(key,header->dst_addr,4);
    }else{
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
    
    if(m->from==MBUF_FROM_WAN){
        rewrite_ip_addr(header,rule->right_addr,0);
        qos_add(m);
    }else{
        rewrite_ip_addr(header,rule->left_addr,1);
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

    PRINT_IP(" ",left_addr);
    PRINT_IP(" ",right_addr);

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

    rule=map_find(left2right_m,(char *)key,&is_found);
    if(NULL==rule) return;

    memcpy(key,rule->id,16);

    map_del(left2right_m,(char *)left_addr,ixc_dnat_del_cb);
    map_del(right2left_m,(char *)key,ixc_dnat_del_cb);
}
