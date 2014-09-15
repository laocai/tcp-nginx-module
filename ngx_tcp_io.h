#ifndef _NGX_TCP_IO_H_
#define _NGX_TCP_IO_H_

#include <ngx_tcp.h>

typedef struct {
    ngx_array_t       cmdpkg_filters;
    cmdpkg_filter_pt  first_filter;
    cmdpkg_filter_pt  last_filter;
} ngx_tcp_cmdpkg_filter_t;

extern ngx_tcp_cmdpkg_filter_t recvpkg_filters;
extern ngx_tcp_cmdpkg_filter_t sendpkg_filters;
ngx_int_t ngx_tcp_cmdpkg_filter_init(ngx_cycle_t *cycle, ngx_tcp_cmdpkg_filter_t *filter);
ngx_int_t ngx_tcp_do_cmdpkg_filter(ngx_tcp_session_t *s, 
    ngx_tcp_cmdpkg_filter_t *f, u_char **pkg, int *pkg_len);

ngx_int_t ngx_tcp_chain_writer(ngx_tcp_session_t *s);
void ngx_tcp_send(ngx_event_t *wev);
long ngx_tcp_send_data(ngx_tcp_ctx_t *ctx, const u_char *data, int len);
long ngx_tcp_send_cmdpkg(ngx_tcp_ctx_t *ctx, u_char *data, int len);

#endif

