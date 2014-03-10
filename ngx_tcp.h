
#ifndef _NGX_TCP_H_INCLUDED_
#define _NGX_TCP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_tcp_cmdso.h>

#if (NGX_TCP_SSL)
#include <ngx_tcp_ssl_module.h>
#endif


typedef struct {
    void                  **main_conf;
    void                  **srv_conf;
} ngx_tcp_conf_ctx_t;


typedef struct {
    u_char                  sockaddr[NGX_SOCKADDRLEN];
    socklen_t               socklen;

    /* server ctx */
    ngx_tcp_conf_ctx_t     *ctx;

    unsigned                bind:1;
    unsigned                wildcard:1;
#if (NGX_TCP_SSL)
    unsigned                ssl:1;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                ipv6only:1;
#endif
    unsigned                so_keepalive:2;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                     tcp_keepidle;
    int                     tcp_keepintvl;
    int                     tcp_keepcnt;
#endif
} ngx_tcp_listen_t;


typedef struct {
    ngx_tcp_conf_ctx_t    *ctx;
    ngx_str_t              addr_text;
#if (NGX_TCP_SSL)
    ngx_uint_t             ssl;    /* unsigned   ssl:1; */
#endif
} ngx_tcp_addr_conf_t;

typedef struct {
    in_addr_t              addr;
    ngx_tcp_addr_conf_t    conf;
} ngx_tcp_in_addr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr        addr6;
    ngx_tcp_addr_conf_t    conf;
} ngx_tcp_in6_addr_t;

#endif


typedef struct {
    /* ngx_tcp_in_addr_t or ngx_tcp_in6_addr_t */
    void                   *addrs;
    ngx_uint_t              naddrs;
} ngx_tcp_port_t;


typedef struct {
    int                    family;
    in_port_t              port;
    ngx_array_t            addrs;       /* array of ngx_tcp_conf_addr_t */
} ngx_tcp_conf_port_t;


typedef struct {
    struct sockaddr       *sockaddr;
    socklen_t              socklen;

    ngx_tcp_conf_ctx_t    *ctx;

    unsigned               bind:1;
    unsigned               wildcard:1;
#if (NGX_TCP_SSL)
    unsigned               ssl:1;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned               ipv6only:1;
#endif
    unsigned               so_keepalive:2;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                    tcp_keepidle;
    int                    tcp_keepintvl;
    int                    tcp_keepcnt;
#endif
} ngx_tcp_conf_addr_t;

/* sizeof(struct sockaddr_un) less than 255 */
#define MAX_UNIX_URL_LEN 255
typedef struct {
  u_char     len;
  u_char     unix_url[MAX_UNIX_URL_LEN];
} unix_listening_info_t;


typedef void *        socketfd_info_tag;
typedef struct {
    /* work process unix-listening info index is ngx_process_slot */
    ngx_int_t            listening_unix_info_i;
    socketfd_info_tag    tag;
} socketfd_info_t;


/* All the address is shm. */
typedef struct {
    /* Array of socketfd_info_t. Array index is socketfd. */
    socketfd_info_t        *socketfd_info;
    /* Array of unix listening info. */
    unix_listening_info_t  *listening_unix_info;
} socketfd_shm_info_t;


typedef struct {
    ngx_path_t                      *path;
    ngx_msec_t                       last;
    ngx_slab_pool_t                 *shpool;
    ngx_shm_zone_t                  *shm_zone;
    
    /* point to ngx_tcp_core_main_conf_t's max_socketfd */
    ngx_int_t                       *max_socketfd_value;
    socketfd_shm_info_t             *info;
} socketfd_shm_t ;


typedef struct {
    ngx_array_t             servers;     /* ngx_tcp_core_srv_conf_t */
    ngx_array_t             listen;      /* ngx_tcp_listen_t */

    ngx_str_t               unix_url;    /* work process unix-listening-path */
    ngx_listening_t        *ls;

    /* max value of socket fd */
    ngx_int_t               max_socketfd_value;
    socketfd_shm_t         *socketfd_shm;

    ngx_log_t              *error_log;
} ngx_tcp_core_main_conf_t;


#define NGX_TCP_CMD_PROTOCOL  0


typedef struct ngx_tcp_protocol_s  ngx_tcp_protocol_t;


typedef struct {
    ngx_tcp_protocol_t    *protocol;

    ngx_msec_t             timeout;
    ngx_msec_t             resolver_timeout;

    ngx_flag_t             so_keepalive;

    ngx_str_t              server_name;

    u_char                *file_name;
    ngx_int_t              line;

    ngx_resolver_t        *resolver;
    size_t                 connection_pool_size;

    /* server ctx */
    ngx_tcp_conf_ctx_t    *ctx;
} ngx_tcp_core_srv_conf_t;


typedef struct {
    ngx_peer_connection_t    upstream;
    ngx_buf_t               *buffer;
} ngx_tcp_proxy_ctx_t;


typedef struct {
    uint32_t                 signature;         /* "TCP" */

    ngx_tcp_ctx_t            tcp_ctx;

    ngx_connection_t        *connection;

    ngx_buf_t               *buffer;           /* recv buf */
    ngx_chain_t             *output_buffer_chain;
    ngx_output_chain_ctx_t  *output_ctx;       /* send buf chain context */

    void                   **ctx;
    void                   **main_conf;
    void                   **srv_conf;

    unsigned                 protocol:3;
    unsigned                 blocked:1;

    ngx_str_t               *addr_text;
} ngx_tcp_session_t;


typedef struct {
    ngx_str_t            *client;
    ngx_tcp_session_t    *session;
} ngx_tcp_log_ctx_t;


#define NGX_TCP_PARSE_INVALID_COMMAND  20


typedef ngx_tcp_session_t *(*ngx_tcp_create_session_pt)(ngx_connection_t *c);
typedef void 
    (*ngx_tcp_init_session_pt)(ngx_tcp_session_t *s, ngx_connection_t *c);
typedef void (*ngx_tcp_finit_session_pt)(ngx_tcp_session_t *s);
typedef void (*ngx_tcp_init_protocol_pt)(ngx_event_t *rev);
typedef ngx_int_t (*ngx_tcp_parse_pkg_pt)(ngx_tcp_session_t *s);

ngx_chain_t *
ngx_tcp_chain_get_free_buf(ngx_output_chain_ctx_t *ctx, size_t total_size);
ngx_int_t ngx_tcp_open_listening_socket(ngx_listening_t  *ls);
ngx_int_t ngx_tcp_chain_writer(void *data, ngx_chain_t *in);

struct ngx_tcp_protocol_s {
    ngx_str_t                   name;
    in_port_t                   port[4];
    ngx_uint_t                  type;

    ngx_tcp_create_session_pt   create_session;
    ngx_tcp_init_session_pt     init_session;
    ngx_tcp_finit_session_pt    finit_session;
    ngx_tcp_init_protocol_pt    init_protocol;
    ngx_tcp_parse_pkg_pt        parse_command;

    ngx_str_t                   internal_server_error;
};

ngx_tcp_session_t *ngx_tcp_create_session(ngx_connection_t *c);


extern  ngx_module_t  ngx_tcp_module;
typedef struct {
    ngx_tcp_protocol_t  *protocol;

    void            *(*create_main_conf)(ngx_conf_t *cf);
    char            *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void            *(*create_srv_conf)(ngx_conf_t *cf);
    char            *(*merge_srv_conf)(ngx_conf_t *cf, void *prev, void *conf);
} ngx_tcp_module_t;


#define NGX_TCP_MODULE         0x504354     /* "TCP" */

#define NGX_TCP_MAIN_CONF      0x02000000
#define NGX_TCP_SRV_CONF       0x04000000


#define NGX_TCP_MAIN_CONF_OFFSET offsetof(ngx_tcp_conf_ctx_t, main_conf)
#define NGX_TCP_SRV_CONF_OFFSET  offsetof(ngx_tcp_conf_ctx_t, srv_conf)


#define ngx_tcp_get_module_ctx(s, module)   (s)->ctx[module.ctx_index]
#define ngx_tcp_set_ctx(s, c, module)       s->ctx[module.ctx_index] = c;
#define ngx_tcp_delete_ctx(s, module)       s->ctx[module.ctx_index] = NULL;


#define ngx_tcp_get_module_main_conf(s, module)  \
    (s)->main_conf[module.ctx_index]
#define ngx_tcp_get_module_srv_conf(s, module)   \
    (s)->srv_conf[module.ctx_index]

#define ngx_tcp_conf_get_module_main_conf(cf, module)              \
    ((ngx_tcp_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_tcp_conf_get_module_srv_conf(cf, module)               \
    ((ngx_tcp_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]


#if (NGX_TCP_SSL)
void ngx_tcp_starttls_handler(ngx_event_t *rev);
ngx_int_t 
ngx_tcp_starttls_only(ngx_tcp_session_t *s, ngx_connection_t *c);
#endif


void ngx_tcp_init_connection(ngx_connection_t *c);

void ngx_tcp_send(ngx_event_t *wev);
long ngx_tcp_send_data(ngx_tcp_ctx_t *ctx, const u_char *data, int len);
void ngx_tcp_close_connection(ngx_connection_t *c);
void ngx_tcp_session_internal_server_error(ngx_tcp_session_t *s);
u_char *ngx_tcp_log_error_msg(ngx_log_t *log, u_char *buf, size_t len);

/* STUB */
void ngx_tcp_proxy_init(ngx_tcp_session_t *s, ngx_addr_t *peer);
/**/


extern ngx_uint_t    ngx_tcp_max_module;
extern ngx_module_t  ngx_tcp_core_module;


#endif /* _NGX_TCP_H_INCLUDED_ */
