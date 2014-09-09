#ifndef _NGX_TCP_EXPORT_H_
#define _NGX_TCP_EXPORT_H_

#include <ngx_tcp_export_func.h>
#include <ngx_tcp_export_data.h>

typedef void *(*ngx_tcp_alloc_pt)(void *pool, size_t size);
typedef ngx_tcp_int_t (*ngx_tcp_pfree_pt)(void *pool, void *p);

struct ngx_tcp_ctx_s {
    /* cmdso_sessioin array. the slot is init in cmdso_load func */
    void                   **cmdso_sessioin;
    void                    *ngx_tcp_session;
    int                      socketfd;
    uint32_t                 pkg_recv_count;
    uint32_t                 pkg_send_count;

    ngx_tcp_log_t            tcp_log_t;
    void                    *pool;
    ngx_tcp_alloc_pt         palloc;
    ngx_tcp_alloc_pt         pcalloc;
    ngx_tcp_pfree_pt         pfree;
};

struct ngx_tcp_cycle_ctx_s {

    ngx_tcp_export_func_t      export_func;
    ngx_tcp_export_data_t      export_data;

    //ngx_tcp_conf_get_str_pt    conf_get_str;
    //ngx_tcp_log_t              tcp_log_t;
    //ngx_tcp_send_data_pt       send_data;
    //ngx_tcp_get_ctx_pt         get_ctx;

    //ngx_tcp_process_info_t    *process_info;
    //volatile uintptr_t        *current_msec;
    //socketfd_shm_info_t       *socketfd_shm_info;
};

#endif

