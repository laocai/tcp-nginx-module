
#ifndef _NGX_TCP_CMD_MODULE_H_INCLUDED_
#define _NGX_TCP_CMD_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_tcp.h>
#include <ngx_map.h>


typedef struct {
    size_t            max_pkg_size;
} ngx_tcp_cmd_srv_conf_t;


typedef struct {
    ngx_tcp_session_t    parent;

    unsigned                 pkghead_parsed:1;    
} ngx_tcp_cmd_session_t;


typedef struct {
    ngx_rbtree_t rbtree;
    ngx_rbtree_node_t sentinel;
} ngx_tcp_cmd_pkg_handler_mgr_t;


typedef struct {
    ngx_tcp_cmd_pkg_handler_mgr_t    pkg_handler_mgr;
    ngx_array_t                      cmdsos; /* ngx_tcp_cmdso_t array */
} ngx_tcp_cmdso_mgr_t;

ngx_int_t ngx_tcp_cmd_conf_get_str(const char *section, 
    const char *k, char **v);

ngx_tcp_session_t *ngx_tcp_cmd_create_session(ngx_connection_t *c);
void ngx_tcp_cmd_init_session(ngx_tcp_session_t *s, ngx_connection_t *c);
void ngx_tcp_cmd_finit_session(ngx_tcp_session_t *s);
void ngx_tcp_cmd_init_protocol(ngx_event_t *rev);
ngx_int_t ngx_tcp_cmd_parse_pkg(ngx_tcp_session_t *s);
cmd_pkg_handler_pt ngx_tcp_cmd_lookup_pkg_handler(uint32_t cmd);

extern ngx_tcp_cmdso_mgr_t *cmdso_mgr;
extern ngx_map_t           *cmdso_conf;
extern ngx_module_t         ngx_tcp_cmd_module;


#endif /* _NGX_TCP_CMD_MODULE_H_INCLUDED_ */

