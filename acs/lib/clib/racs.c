#define  PY_SSIZE_T_CLEAN
#define  PY_SSIZE_T_CLEAN

#include<Python.h>
#include<structmember.h>
#include<execinfo.h>
#include<signal.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>

#include "mbuf.h"
#include "debug.h"
#include "ip.h"
#include "ipv6.h"
#include "racs.h"
#include "dnat.h"
#include "qos.h"

#include "../../../pywind/clib/sysloop.h"
#include "../../../pywind/clib/netif/tuntap.h"
#include "../../../pywind/clib/netutils.h"

typedef struct{
    PyObject_HEAD
}racs_object;

/// 发送IP数据包回调函数
static PyObject *ip_sent_cb=NULL;


static void ixc_segfault_handle(int signum)
{
    void *bufs[4096];
    char **strs;
    int nptrs;

    nptrs=backtrace(bufs,4096);
    strs=backtrace_symbols(bufs,nptrs);
    if(NULL==strs) return;

    for(int n=0;n<nptrs;n++){
        fprintf(stderr,"%s\r\n",strs[n]);
    }
    free(strs);
    exit(EXIT_FAILURE);
}

int netpkt_send(struct mbuf *m)
{
    PyObject *arglist,*result;

    if(NULL==ip_sent_cb){
        STDERR("not set ip_sent_cb\r\n");
        return -1;
    }

    arglist=Py_BuildValue("(y#y#i)",m->id,16,m->data+m->begin,m->end-m->begin,m->from);
    result=PyObject_CallObject(ip_sent_cb,arglist);
 
    Py_XDECREF(arglist);
    Py_XDECREF(result);

    mbuf_put(m);

    return 0;
}

static void
racs_dealloc(racs_object *self)
{
    qos_uninit();
    ixc_dnat_uninit();
    sysloop_uninit();
    mbuf_uninit();
}

static PyObject *
racs_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    racs_object *self;
    int rs=0;
    self=(racs_object *)type->tp_alloc(type,0);
    if(NULL==self) return NULL;

    rs=mbuf_init(64);
    if(rs<0){
        STDERR("cannot init mbuf\r\n");
        return NULL;
    }

    rs=sysloop_init();
    if(rs<0){
        STDERR("cannot init sysloop\r\n");
        return NULL;
    }

    rs=qos_init();
    if(rs<0){
        STDERR("cannot init qos\r\n");
        return NULL;
    }

    rs=ixc_dnat_init();
    if(rs<0){
        STDERR("cannot init dnat\r\n");
        return NULL;
    }

    signal(SIGSEGV,ixc_segfault_handle);

    return (PyObject *)self;
}

static int
racs_init(racs_object *self,PyObject *args,PyObject *kwds)
{
    PyObject *fn_ip_sent_cb;
    PyObject *fn_udp_recv_cb;

    if(!PyArg_ParseTuple(args,"O",&fn_ip_sent_cb,&fn_udp_recv_cb)) return -1;
    if(!PyCallable_Check(fn_ip_sent_cb)){
        PyErr_SetString(PyExc_TypeError,"ip sent callback function  must be callable");
        return -1;
    }

    Py_XDECREF(ip_sent_cb);

    ip_sent_cb=fn_ip_sent_cb;

    Py_INCREF(ip_sent_cb);

    return 0;
}

/// 处理接收到的网络数据包
static PyObject *
racs_netpkt_handle(PyObject *self,PyObject *args)
{
    const char *s,*id;
    Py_ssize_t size,id_size;
    struct mbuf *m;
    int from;

    if(!PyArg_ParseTuple(args,"y#y#i",&id,&id_size,&s,&size,&from)) return NULL;
    if(size<21){
        STDERR("wrong IP data format\r\n");
        Py_RETURN_FALSE;
    }

    m=mbuf_get();
    if(NULL==m){
        STDERR("cannot get mbuf\r\n");
        Py_RETURN_FALSE;
    }

    m->begin=m->offset=MBUF_BEGIN;
    m->end=m->tail=m->begin+size;

    m->from=from;

    memcpy(m->data+m->offset,s,size);
    memcpy(m->id,id,16);

    ip_handle(m);

    Py_RETURN_TRUE;
}

static PyObject *
racs_rule_add(PyObject *self,PyObject *args)
{
    const char *left_ip,*right_ip;
    unsigned char *id;
    int is_ipv6,rs;
    Py_ssize_t id_size;
    unsigned char left_net[256];
    unsigned char right_net[256];

    if(!PyArg_ParseTuple(args,"y#ssp",&id,&id_size,&left_ip,&right_ip,&is_ipv6)) return NULL;

    if(id_size!=16){
        Py_RETURN_FALSE;
    }

    if(is_ipv6){
        inet_pton(AF_INET6,left_ip,left_net);
        inet_pton(AF_INET6,right_ip,right_net);
    }else{
        inet_pton(AF_INET,left_ip,left_net);
        inet_pton(AF_INET,right_ip,right_net);
    }

    rs=ixc_dnat_rule_add(id,left_net,right_net,is_ipv6);
    if(rs<0){
        Py_RETURN_FALSE;
    }

    Py_RETURN_TRUE;
}

static PyObject *
racs_rule_del(PyObject *self,PyObject *args)
{
    const char *s;
    unsigned char buf[256];
    int is_ipv6;

    if(!PyArg_ParseTuple(args,"sp",&s,&is_ipv6)) return NULL;

    if(is_ipv6) inet_pton(AF_INET6,s,buf);
    else inet_pton(AF_INET,s,buf);

    ixc_dnat_rule_del(buf,is_ipv6);


    Py_RETURN_NONE;
}

static PyObject *
racs_local_rule_set(PyObject *self,PyObject *args)
{
    const char *old_ip,*new_ip;
    int is_ipv6;
    unsigned char old_net[256];
    unsigned char new_net[256];

    if(!PyArg_ParseTuple(args,"ssp",&old_ip,&new_ip,&is_ipv6)) return NULL;

    if(is_ipv6){
        inet_pton(AF_INET6,old_ip,old_net);
        inet_pton(AF_INET6,new_ip,new_net);
    }else{
        inet_pton(AF_INET,old_ip,old_net);
        inet_pton(AF_INET,new_ip,new_net);
    }

    ixc_dnat_local_rule_set(old_net,new_net,is_ipv6);
    Py_RETURN_NONE;
}

static PyObject *
racs_tcp_mss_set(PyObject *self,PyObject *args)
{
    unsigned short mss;
    int is_ipv6,rs;

    if(!PyArg_ParseTuple(args,"Hp",&mss,&is_ipv6)) return NULL;

    rs=ixc_dnat_tcp_mss_set(mss,is_ipv6);
    if(rs<0){
        Py_RETURN_FALSE;
    }

    Py_RETURN_TRUE;
}

/// 打开tun设备
static PyObject *
racs_tun_open(PyObject *self,PyObject *args)
{
    const char *name;
    char new_name[512];
    int fd;

    if(!PyArg_ParseTuple(args,"s",&name)) return NULL;
    
    strcpy(new_name,name);

    fd=tundev_create(new_name);
    if(fd<0){
        return PyLong_FromLong(fd);
    }

    tundev_up(name);
    tundev_set_nonblocking(fd);

    return PyLong_FromLong(fd);
}

/// 关闭tun设备
static PyObject *
racs_tun_close(PyObject *self,PyObject *args)
{
    const char *name;
    int fd;

    if(!PyArg_ParseTuple(args,"is",&fd,&name)) return NULL;

    tundev_close(fd,name);

    Py_RETURN_NONE;
}

static PyObject *
racs_loop(PyObject *self,PyObject *args)
{
    sysloop_do();

    if(qos_have_data()){
        Py_RETURN_FALSE;
    }

    Py_RETURN_TRUE;
}

static PyObject *
racs_clog_set(PyObject *self,PyObject *args)
{
    const char *stdout_path,*stderr_path;

    if(!PyArg_ParseTuple(args,"ss",&stdout_path,&stderr_path)) return NULL;

    if(freopen(stdout_path,"a+",stdout)==NULL){
        STDERR("cannot set stdout\r\n");
        return NULL;
    }

    if(freopen(stderr_path,"a+",stderr)==NULL){
        STDERR("cannot set stderr\r\n");
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyMemberDef racs_members[]={
    {NULL}
};

static PyMethodDef racs_methods[]={
    {"netpkt_handle",(PyCFunction)racs_netpkt_handle,METH_VARARGS,"handle ip data packet"},
    {"rule_add",(PyCFunction)racs_rule_add,METH_VARARGS,"dnat rule add"},
    {"rule_del",(PyCFunction)racs_rule_del,METH_VARARGS,"dnat rule del"},
    {"local_rule_set",(PyCFunction)racs_local_rule_set,METH_VARARGS,"set local rule"},
    {"tcp_mss_set",(PyCFunction)racs_tcp_mss_set,METH_VARARGS,"set tcp mss value"},

    {"tun_open",(PyCFunction)racs_tun_open,METH_VARARGS,"open tun device"},
    {"tun_close",(PyCFunction)racs_tun_close,METH_VARARGS,"close tun device"},

    {"loop",(PyCFunction)racs_loop,METH_NOARGS,"do loop"},
    {"clog_set",(PyCFunction)racs_clog_set,METH_VARARGS,"set C language log path"},
    
    {NULL,NULL,0,NULL}
};

static PyTypeObject racs_type={
    PyVarObject_HEAD_INIT(NULL,0)
    .tp_name="racs.racs",
    .tp_doc="python racs helper library",
    .tp_basicsize=sizeof(racs_object),
    .tp_itemsize=0,
    .tp_flags=Py_TPFLAGS_DEFAULT,
    .tp_new=racs_new,
    .tp_init=(initproc)racs_init,
    .tp_dealloc=(destructor)racs_dealloc,
    .tp_members=racs_members,
    .tp_methods=racs_methods
};

static struct PyModuleDef racs_module={
    PyModuleDef_HEAD_INIT,
    "racs",
    NULL,
    -1,
    racs_methods,
    NULL,NULL,NULL,NULL
};

PyMODINIT_FUNC
PyInit_racs(void){
    PyObject *m;
    const char *const_names[] = {
        "FROM_LAN",
        "FROM_WAN"
	};

	const int const_values[] = {
        MBUF_FROM_LAN,
        MBUF_FROM_WAN
	};
    
    int const_count = sizeof(const_names) / sizeof(NULL);

    if(PyType_Ready(&racs_type) < 0) return NULL;

    m=PyModule_Create(&racs_module);
    if(NULL==m) return NULL;

    for (int n = 0; n < const_count; n++) {
		if (PyModule_AddIntConstant(m, const_names[n], const_values[n]) < 0) return NULL;
	}

    Py_INCREF(&racs_type);
    if(PyModule_AddObject(m,"racs",(PyObject *)&racs_type)<0){
        Py_DECREF(&racs_type);
        Py_DECREF(m);
        return NULL;
    }
    
    return m;
}
