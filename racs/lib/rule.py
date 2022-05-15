#!/usr/bin/env python3

import pywind.lib.netutils as netutils
import racs.lib.logging as logging

class RuleErr(Exception):pass

def rule_parse(fpath:str):
    fdst=open(fpath,"r")
    errmsg=None
    is_err=False
    results=[]

    for line in fdst:
        line=line.strip()
        line=line.strip("\r")
        line=line.strip("\n")

        if not line:continue
        # 去除注释
        if line[0]=="#":continue

        p=line.find("->")

        if p<1:
            is_err=True
            errmsg="wrong rule %s at file %s" % (line,fpath)
            break
        left=line[0:p].strip()
        p+=2
        right=line[p:].strip()

        # 检查是否是IP地址
        if not netutils.is_ipv4_address(left) and not netutils.is_ipv6_address(left):
            errmsg="wrong IP address %s at file %s" % (line,fpath)
            is_err=True
            break
        if not netutils.is_ipv4_address(right) and not netutils.is_ipv6_address(right):
            errmsg="wrong IP address %s at file %s" % (line,fpath)
            is_err=True
            break

        a=netutils.is_ipv4_address(left)
        b=netutils.is_ipv4_address(right)
        if a!=b:
            is_err=True
            errmsg="different type IP address %s at file %s" % (line,fpath)
            break
        
        results.append((left,right,netutils.is_ipv6_address(left),))
    
    fdst.close()

    if is_err:
        raise RuleErr(errmsg)
    return results


class rule_manager(object):
    """规则管理器"""
    __rules=None
    __rules_reverse=None

    def __init__(self):
        self.__rules={}
        self.__rules_reverse={}

    def load(self,user_id:bytes,fpath:str):
        """加载规则
        """
        try:
            rules=rule_parse(fpath)
        except:
            logging.print_error()
            return False
        
        flags=True
        
        for left,right,is_ipv6 in rules:
            if left in self.__rules:
                flags=False
                logging.print_error("conflict rule %s->%s at file %s" % (left,right,fpath,))
                break
            
            if left in self.__rules_reverse:
                flags=False
                logging.print_error("conflict rule %s->%s at file %s" % (left,right,fpath,))
                break

            if right in self.__rules_reverse:
                flags=False
                logging.print_error("conflict rule %s->%s at file %s" % (left,right,fpath,))
                break

            if left==right:
                flags=False
                logging.print_error("wrong rule %s->%s at file %s" % (left,right,fpath,))
                break
            
            self.__rules[left]=(user_id,right,is_ipv6,)
            self.__rules_reverse[right]=(left,is_ipv6,)
        
        return flags

    @property
    def rules(self):
        return self.__rules
    
    def reset(self):
        self.__rules={}
        self.__rules_reverse={}