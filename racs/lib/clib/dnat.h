#ifndef IXC_DNAT_H
#define IXC_DNAT_H
/**
# 外部网络访问局域网,外部IP地址看成LEFT,局域网IP地址看成RIGHT
#
**/

#include "mbuf.h"

#include "../../../pywind/clib/map.h"

struct ixc_dnat{
    struct map *left2right;
    struct map *right2left;
    
    struct map *left2right_v6;
    struct map *right2left_v6;
};

struct ixc_dnat_rule{
    unsigned char id[16];
    unsigned char left_addr[16];
    unsigned char right_addr[16];

    unsigned int refcnt;
    int is_ipv6;
};

int ixc_dnat_init(void);
void ixc_dnat_uninit(void);

void ixc_dnat_handle(struct mbuf *m,void *ip_header);

int ixc_dnat_rule_add(const unsigned char *_id,const unsigned char *left_addr,const unsigned char *right_addr,int is_ipv6);
void ixc_dnat_rule_del(unsigned char *left_addr,int is_ipv6);

#endif