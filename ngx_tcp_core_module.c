
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_tcp.h>


static void *ngx_tcp_core_create_main_conf(ngx_conf_t *cf);
static void *ngx_tcp_core_create_srv_conf(ngx_conf_t *cf);
static char *ngx_tcp_core_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_tcp_instruct_unix_listen(ngx_cycle_t *cycle);
static char *ngx_tcp_core_server(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_tcp_core_listen(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_tcp_socketfd_shm_set_slot(ngx_conf_t *cf, 
    ngx_command_t *cmd, void *conf);
static char *ngx_tcp_core_protocol(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_tcp_core_resolver(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_tcp_core_error_log(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_tcp_process_init(ngx_cycle_t *cycle);


static ngx_conf_deprecated_t  ngx_conf_deprecated_so_keepalive = {
    ngx_conf_deprecated, "so_keepalive",
    "so_keepalive\" parameter of the \"listen"
};

static ngx_command_t  ngx_tcp_core_commands[] = {

    { ngx_string("error_log"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_1MORE,
      ngx_tcp_core_error_log,
      NGX_TCP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("max_socketfd_value"),
      NGX_TCP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_TCP_MAIN_CONF_OFFSET,
      offsetof(ngx_tcp_core_main_conf_t, max_socketfd_value),
      NULL },
      
    { ngx_string("worker_process_unix_listen"),
      NGX_TCP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_TCP_MAIN_CONF_OFFSET,
      offsetof(ngx_tcp_core_main_conf_t, unix_url),
      NULL },

    { ngx_string("socketfd_shm"),
      NGX_TCP_MAIN_CONF|NGX_CONF_1MORE,
      ngx_tcp_socketfd_shm_set_slot,
      NGX_TCP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("server"),
      NGX_TCP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_tcp_core_server,
      0,
      0,
      NULL },

    { ngx_string("listen"),
      NGX_TCP_SRV_CONF|NGX_CONF_TAKE12,
      ngx_tcp_core_listen,
      NGX_TCP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("protocol"),
      NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_tcp_core_protocol,
      NGX_TCP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("connection_pool_size"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_core_srv_conf_t, connection_pool_size),
      NULL },

    { ngx_string("so_keepalive"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_core_srv_conf_t, so_keepalive),
      &ngx_conf_deprecated_so_keepalive },

    { ngx_string("timeout"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_core_srv_conf_t, timeout),
      NULL },

    { ngx_string("server_name"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_core_srv_conf_t, server_name),
      NULL },

    { ngx_string("resolver"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_1MORE,
      ngx_tcp_core_resolver,
      NGX_TCP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("resolver_timeout"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_core_srv_conf_t, resolver_timeout),
      NULL },

      ngx_null_command
};


static ngx_tcp_module_t  ngx_tcp_core_module_ctx = {
    NULL,                                     /* protocol */

    ngx_tcp_core_create_main_conf,        /* create main configuration */
    NULL,                                 /* init main configuration */

    ngx_tcp_core_create_srv_conf,         /* create server configuration */
    ngx_tcp_core_merge_srv_conf           /* merge server configuration */
};


ngx_module_t  ngx_tcp_core_module = {
    NGX_MODULE_V1,
    &ngx_tcp_core_module_ctx,          /* module context */
    ngx_tcp_core_commands,             /* module directives */
    NGX_TCP_MODULE,                    /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    ngx_tcp_process_init,              /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_tcp_core_create_main_conf(ngx_conf_t *cf)
{
    ngx_tcp_core_main_conf_t  *cmcf;

    cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_core_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&cmcf->servers, cf->pool, 4,
                       sizeof(ngx_tcp_core_srv_conf_t *))
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&cmcf->listen, cf->pool, 4, sizeof(ngx_tcp_listen_t))
        != NGX_OK)
    {
        return NULL;
    }
    
    cmcf->max_socketfd_value = NGX_CONF_UNSET;
    cmcf->socketfd_shm = NGX_CONF_UNSET_PTR;

    return cmcf;
}


static void *
ngx_tcp_core_create_srv_conf(ngx_conf_t *cf)
{
    ngx_tcp_core_srv_conf_t  *cscf;

    cscf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_core_srv_conf_t));
    if (cscf == NULL) {
        return NULL;
    }

    cscf->timeout = NGX_CONF_UNSET_MSEC;
    cscf->resolver_timeout = NGX_CONF_UNSET_MSEC;
    cscf->so_keepalive = NGX_CONF_UNSET;

    cscf->resolver = NGX_CONF_UNSET_PTR;

    cscf->file_name = cf->conf_file->file.name.data;
    cscf->line = cf->conf_file->line;
    cscf->connection_pool_size = NGX_CONF_UNSET_SIZE;

    return cscf;
}


static char *
ngx_tcp_core_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_tcp_core_srv_conf_t *prev = parent;
    ngx_tcp_core_srv_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 60000);
    ngx_conf_merge_msec_value(conf->resolver_timeout, prev->resolver_timeout,
                              30000);
    ngx_conf_merge_size_value(conf->connection_pool_size,
                              prev->connection_pool_size, 2048);

    ngx_conf_merge_value(conf->so_keepalive, prev->so_keepalive, 0);


    ngx_conf_merge_str_value(conf->server_name, prev->server_name, "");

    if (conf->server_name.len == 0) {
        conf->server_name = cf->cycle->hostname;
    }

    if (conf->protocol == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "unknown tcp protocol for server in %s:%ui",
                      conf->file_name, conf->line);
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_ptr_value(conf->resolver, prev->resolver, NULL);
    
    /* for unix domain socket */
    prev->protocol = conf->protocol;
    prev->timeout = conf->timeout;

    return NGX_CONF_OK;
}

static char *
ngx_tcp_core_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_core_main_conf_t *cmcf = conf;

    ngx_str_t  *value, name;

    if (cmcf->error_log) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "stderr") == 0) {
        ngx_str_null(&name);

    } else {
        name = value[1];
    }

    cmcf->error_log = ngx_log_create(cf->cycle, &name);
    if (cmcf->error_log == NULL) {
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 2) {
        cmcf->error_log->log_level = NGX_LOG_ERR;
        return NGX_CONF_OK;
    }

    return ngx_log_set_levels(cf, cmcf->error_log);
}


static ngx_int_t
ngx_tcp_socketfd_shm_init(ngx_shm_zone_t *shm_zone, void *data)
{
    /* socketfd_shm_t            *ocache = data; */

    socketfd_shm_t            *socketfd_shm;
    ngx_slab_pool_t           *sp;

    socketfd_shm = shm_zone->data;

    /* if (ocache) {
        if (ngx_strcmp(socketfd_shm->path->name.data, ocache->path->name.data) != 0) {
            ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                          "cache \"%V\" uses the \"%V\" cache path "
                          "while previously it used the \"%V\" cache path",
                          &shm_zone->shm.name, &socketfd_shm->path->name,
                          &ocache->path->name);

            return NGX_ERROR;
        }

        socketfd_shm->shpool = ocache->shpool;
    } else {
        socketfd_shm->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    } */
    socketfd_shm->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    sp = socketfd_shm->shpool;
    /* ngx_memzero(sp->start, sp->end - sp->start); */
    socketfd_shm->info = (socketfd_shm_info_t *) sp->start;
    socketfd_shm->info->socketfd_info = 
        (socketfd_info_t *)(sp->start + sizeof(socketfd_shm_info_t));
    socketfd_shm->info->listening_unix_info = (unix_listening_info_t *)
        ((u_char *)(socketfd_shm->info->socketfd_info) + 
            *(socketfd_shm->max_socketfd_value) * sizeof(socketfd_info_t));

    return NGX_OK;
}


static char *
ngx_tcp_socketfd_shm_set_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_core_main_conf_t      *cmcf = conf;
    socketfd_shm_t                *socketfd_shm;
    ngx_str_t                      s, name, *value;
    u_char                        *p;
    ssize_t                        size;
    ngx_uint_t                     i;

    socketfd_shm = ngx_pcalloc(cf->pool, sizeof(socketfd_shm_t));
    if (cmcf->socketfd_shm == NULL) {
        return NGX_CONF_ERROR;
    }
    socketfd_shm->path = ngx_pcalloc(cf->pool, sizeof(ngx_path_t));
    if (socketfd_shm->path == NULL) {
        return NGX_CONF_ERROR;
    }
    socketfd_shm->max_socketfd_value = &cmcf->max_socketfd_value;

    value = cf->args->elts;

    socketfd_shm->path->name = value[1];

    if (socketfd_shm->path->name.data[socketfd_shm->path->name.len - 1] 
        == '/') {
        socketfd_shm->path->name.len--;
    }

    if (ngx_conf_full_name(cf->cycle, &socketfd_shm->path->name, 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    size = 0;
    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "keys_zone=", 10) == 0) {

            name.data = value[i].data + 10;

            p = (u_char *) ngx_strchr(name.data, ':');

            if (p) {
                name.len = p - name.data;

                p++;

                s.len = value[i].data + value[i].len - p;
                s.data = p;

                size = ngx_parse_size(&s);
                if (size > 8191) {
                    continue;
                }
            }

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid keys zone size \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }
    }

    if (name.len == 0 || size == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"keys_zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }
    
    socketfd_shm->path->manager = NULL;
    socketfd_shm->path->loader = NULL;
    socketfd_shm->path->data = socketfd_shm;
    socketfd_shm->path->conf_file = cf->conf_file->file.name.data;
    socketfd_shm->path->line = cf->conf_file->line;

    if (ngx_add_path(cf, &socketfd_shm->path) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    socketfd_shm->shm_zone = ngx_shared_memory_add(cf, &name, size, cmd->post);
    if (socketfd_shm->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (socketfd_shm->shm_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate zone \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    socketfd_shm->shm_zone->init = ngx_tcp_socketfd_shm_init;
    socketfd_shm->shm_zone->data = socketfd_shm;

    cmcf->socketfd_shm = socketfd_shm;

    return NGX_CONF_OK;
}


static char *
ngx_tcp_core_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                       *rv;
    void                       *mconf;
    ngx_uint_t                  m;
    ngx_conf_t                  pcf;
    ngx_tcp_module_t           *module;
    ngx_tcp_conf_ctx_t         *ctx, *tcp_ctx;
    ngx_tcp_core_srv_conf_t    *cscf, **cscfp;
    ngx_tcp_core_main_conf_t   *cmcf;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    tcp_ctx = cf->ctx;
    ctx->main_conf = tcp_ctx->main_conf;

    /* the server{}'s srv_conf */

    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_tcp_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_TCP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->srv_conf[ngx_modules[m]->ctx_index] = mconf;
        }
    }

    /* the server configuration context */

    cscf = ctx->srv_conf[ngx_tcp_core_module.ctx_index];
    cscf->ctx = ctx;

    cmcf = ctx->main_conf[ngx_tcp_core_module.ctx_index];

    cscfp = ngx_array_push(&cmcf->servers);
    if (cscfp == NULL) {
        return NGX_CONF_ERROR;
    }

    *cscfp = cscf;


    /* parse inside server{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_TCP_SRV_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    return rv;
}


static char *
ngx_tcp_core_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_core_srv_conf_t    *cscf = conf;

    size_t                      len, off;
    in_port_t                   port;
    ngx_str_t                  *value;
    ngx_url_t                   u;
    ngx_uint_t                  i, m;
    struct sockaddr            *sa;
    ngx_tcp_listen_t           *ls;
    ngx_tcp_module_t           *module;
    struct sockaddr_in         *sin;
    ngx_tcp_core_main_conf_t   *cmcf;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6        *sin6;
#endif

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.listen = 1;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in \"%V\" of the \"listen\" directive",
                               u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    cmcf = ngx_tcp_conf_get_module_main_conf(cf, ngx_tcp_core_module);

    ls = cmcf->listen.elts;

    for (i = 0; i < cmcf->listen.nelts; i++) {

        sa = (struct sockaddr *) ls[i].sockaddr;

        if (sa->sa_family != u.family) {
            continue;
        }

        switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            off = offsetof(struct sockaddr_in6, sin6_addr);
            len = 16;
            sin6 = (struct sockaddr_in6 *) sa;
            port = sin6->sin6_port;
            break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
        case AF_UNIX:
            off = offsetof(struct sockaddr_un, sun_path);
            len = sizeof(((struct sockaddr_un *) sa)->sun_path);
            port = 0;
            break;
#endif

        default: /* AF_INET */
            off = offsetof(struct sockaddr_in, sin_addr);
            len = 4;
            sin = (struct sockaddr_in *) sa;
            port = sin->sin_port;
            break;
        }

        if (ngx_memcmp(ls[i].sockaddr + off, u.sockaddr + off, len) != 0) {
            continue;
        }

        if (port != u.port) {
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate \"%V\" address and port pair", &u.url);
        return NGX_CONF_ERROR;
    }

    ls = ngx_array_push(&cmcf->listen);
    if (ls == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(ls, sizeof(ngx_tcp_listen_t));

    ngx_memcpy(ls->sockaddr, u.sockaddr, u.socklen);

    ls->socklen = u.socklen;
    ls->wildcard = u.wildcard;
    ls->ctx = cf->ctx;

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    ls->ipv6only = 1;
#endif

    if (cscf->protocol == NULL) {
        for (m = 0; ngx_modules[m]; m++) {
            if (ngx_modules[m]->type != NGX_TCP_MODULE) {
                continue;
            }

            module = ngx_modules[m]->ctx;

            if (module->protocol == NULL) {
                continue;
            }

            for (i = 0; module->protocol->port[i]; i++) {
                if (module->protocol->port[i] == u.port) {
                    cscf->protocol = module->protocol;
                    break;
                }
            }
        }
    }

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strcmp(value[i].data, "bind") == 0) {
            ls->bind = 1;
            continue;
        }

        if (ngx_strncmp(value[i].data, "ipv6only=o", 10) == 0) {
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
            struct sockaddr  *sa;
            u_char            buf[NGX_SOCKADDR_STRLEN];

            sa = (struct sockaddr *) ls->sockaddr;

            if (sa->sa_family == AF_INET6) {

                if (ngx_strcmp(&value[i].data[10], "n") == 0) {
                    ls->ipv6only = 1;

                } else if (ngx_strcmp(&value[i].data[10], "ff") == 0) {
                    ls->ipv6only = 0;

                } else {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "invalid ipv6only flags \"%s\"",
                                       &value[i].data[9]);
                    return NGX_CONF_ERROR;
                }

                ls->bind = 1;

            } else {
                len = ngx_sock_ntop(sa, buf, NGX_SOCKADDR_STRLEN, 1);

                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "ipv6only is not supported "
                                   "on addr \"%*s\", ignored", len, buf);
            }

            continue;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "bind ipv6only is not supported "
                               "on this platform");
            return NGX_CONF_ERROR;
#endif
        }

        if (ngx_strcmp(value[i].data, "ssl") == 0) {
#if (NGX_TCP_SSL)
            ls->ssl = 1;
            continue;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the \"ssl\" parameter requires "
                               "ngx_tcp_ssl_module");
            return NGX_CONF_ERROR;
#endif
        }

        if (ngx_strncmp(value[i].data, "so_keepalive=", 13) == 0) {

            if (ngx_strcmp(&value[i].data[13], "on") == 0) {
                ls->so_keepalive = 1;

            } else if (ngx_strcmp(&value[i].data[13], "off") == 0) {
                ls->so_keepalive = 2;

            } else {

#if (NGX_HAVE_KEEPALIVE_TUNABLE)
                u_char     *p, *end;
                ngx_str_t   s;

                end = value[i].data + value[i].len;
                s.data = value[i].data + 13;

                p = ngx_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    ls->tcp_keepidle = ngx_parse_time(&s, 1);
                    if (ls->tcp_keepidle == (time_t) NGX_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                p = ngx_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    ls->tcp_keepintvl = ngx_parse_time(&s, 1);
                    if (ls->tcp_keepintvl == (time_t) NGX_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                if (s.data < end) {
                    s.len = end - s.data;

                    ls->tcp_keepcnt = ngx_atoi(s.data, s.len);
                    if (ls->tcp_keepcnt == NGX_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                if (ls->tcp_keepidle == 0 && ls->tcp_keepintvl == 0
                    && ls->tcp_keepcnt == 0)
                {
                    goto invalid_so_keepalive;
                }

                ls->so_keepalive = 1;

#else

                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "the \"so_keepalive\" parameter accepts "
                                   "only \"on\" or \"off\" on this platform");
                return NGX_CONF_ERROR;

#endif
            }

            ls->bind = 1;

            continue;

#if (NGX_HAVE_KEEPALIVE_TUNABLE)
        invalid_so_keepalive:

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid so_keepalive value: \"%s\"",
                               &value[i].data[13]);
            return NGX_CONF_ERROR;
#endif
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the invalid \"%V\" parameter", &value[i]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_tcp_instruct_unix_listen(ngx_cycle_t *cycle)
{
    ngx_tcp_core_main_conf_t   *cmcf;
    ngx_tcp_conf_ctx_t         *ctx;

    unix_listening_info_t      *unix_info;
    size_t                      len;
    ngx_listening_t            *ls;
    ngx_url_t                   u;
    struct sockaddr            *sa;
    u_char                      text[NGX_SOCKADDR_STRLEN + 1];

    ctx = (ngx_tcp_conf_ctx_t *)ngx_get_conf(cycle->conf_ctx, ngx_tcp_module);
    cmcf = ngx_tcp_get_module_main_conf(ctx, ngx_tcp_core_module);

    ngx_memzero(&u, sizeof(ngx_url_t));
    ngx_conf_full_name(cycle, &cmcf->unix_url, 0);
    /* ngx_pid to string len is less than 21 - strlen("unix:") */
    u.url.data = ngx_pcalloc(cycle->pool, cmcf->unix_url.len + 21);
    ngx_sprintf(u.url.data, "%s%V%d", "unix:", &cmcf->unix_url, ngx_pid);
    u.url.len = ngx_strlen(u.url.data);
    u.listen = 1;
    cmcf->unix_url = u.url;

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0, 
            "ngx_tcp_instruct_unix_listen|unix_url=%V,len=%d", 
                  &u.url, u.url.len);

    if (ngx_parse_url(cycle->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                               "%s in \"%V\" of the \"listen\" directive",
                               u.err, &u.url);
        }

        return NGX_ERROR;
    }

    unix_info = cmcf->socketfd_shm->info->listening_unix_info + ngx_process_slot;
    ngx_memzero(unix_info, sizeof(unix_listening_info_t));
    unix_info->len = u.url.len;
    ngx_memcpy(unix_info->unix_url, u.url.data, u.url.len);

    ls = ngx_pcalloc(cycle->pool, sizeof(ngx_listening_t));
    if (ls == NULL) {
        goto failed;
    }
    sa = ngx_pcalloc(cycle->pool, u.socklen);
    if (sa == NULL) {
        goto failed;
    }

    ngx_memcpy(sa, u.sockaddr, u.socklen);

    ls->sockaddr = sa;
    ls->socklen = u.socklen;

    len = ngx_sock_ntop(sa, text, NGX_SOCKADDR_STRLEN, 1);
    ls->addr_text.len = len;

    ls->addr_text_max_len = NGX_UNIX_ADDRSTRLEN;
    len++;
    ls->addr_text.data = ngx_pcalloc(cycle->pool, len);
    if (ls->addr_text.data == NULL) {
        goto failed;
    }
    ngx_memcpy(ls->addr_text.data, text, len);

    ls->fd = (ngx_socket_t) -1;
    ls->type = SOCK_STREAM;

    ls->backlog = NGX_LISTEN_BACKLOG;
    ls->rcvbuf = -1;
    ls->sndbuf = -1;

#if (NGX_HAVE_SETFIB)
    ls->setfib = -1;
#endif

    ls->addr_ntop = 1;
    ls->handler = ngx_tcp_init_connection;
    ls->pool_size = 8192;

    ls->logp = &cycle->new_log;
    ls->log.data = &ls->addr_text;
    ls->log.handler = ngx_accept_log_error;

    cmcf->ls = ls;

    return NGX_OK;

failed:
    return NGX_ERROR;
}


static char *
ngx_tcp_core_protocol(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_core_srv_conf_t  *cscf = conf;
    ngx_str_t                *value;
    ngx_uint_t                m;
    ngx_tcp_module_t         *module;

    value = cf->args->elts;

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_TCP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;

        if (module->protocol
            && ngx_strcmp(module->protocol->name.data, value[1].data) == 0)
        {
            cscf->protocol = module->protocol;

            return NGX_CONF_OK;
        }
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "unknown protocol \"%V\"", &value[1]);
    return NGX_CONF_ERROR;
}


static char *
ngx_tcp_core_resolver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_core_srv_conf_t  *cscf = conf;

    ngx_str_t  *value;

    value = cf->args->elts;

    if (cscf->resolver != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    if (ngx_strcmp(value[1].data, "off") == 0) {
        cscf->resolver = NULL;
        return NGX_CONF_OK;
    }

    cscf->resolver = ngx_resolver_create(cf, &value[1], cf->args->nelts - 1);
    if (cscf->resolver == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static ngx_int_t 
ngx_tcp_process_init(ngx_cycle_t *cycle)
{
    ngx_int_t                   rc;
    ngx_tcp_core_main_conf_t   *cmcf;
    ngx_tcp_conf_ctx_t         *ctx;
    ngx_listening_t            *ls;
    ngx_connection_t           *c;
    ngx_event_t                *rev;
    ngx_tcp_port_t             *mport;
    ngx_tcp_in_addr_t          *addrs;

    rc = ngx_tcp_instruct_unix_listen(cycle);
    if (NGX_OK != rc) {
        return rc;
    }
    ctx = (ngx_tcp_conf_ctx_t *)ngx_get_conf(cycle->conf_ctx, ngx_tcp_module);
    cmcf = ngx_tcp_get_module_main_conf(ctx, ngx_tcp_core_module);
    ls = cmcf->ls;
    rc = ngx_tcp_open_listening_socket(ls);
    if (NGX_OK != rc) {
        return rc;
    }
    mport = ngx_palloc(cycle->pool, sizeof(ngx_tcp_port_t));
    if (mport == NULL) {
        return NGX_ERROR;
    }
    mport->naddrs = 1;
    mport->addrs = ngx_pcalloc(cycle->pool,
                               mport->naddrs * sizeof(ngx_tcp_in_addr_t));
    if (mport->addrs == NULL) {
        return NGX_ERROR;
    }
    addrs = mport->addrs;
    addrs->conf.ctx = ctx;
    addrs->conf.addr_text= cmcf->unix_url;
    ls->servers = mport;

    if (cmcf->error_log == NULL) {
        ls->logp = cycle->log;
    } else {
        ls->logp = cmcf->error_log;
    }
    ls->log = *(ls->logp);
    ls->log.data = &ls->addr_text;
    ls->log.handler = ngx_accept_log_error;

    c = ngx_get_connection(ls->fd, cycle->log);
    // c->log = &ls->log;
    c->log = ls->logp;
    c->listening = ls;
    ls->connection = c;

    rev = c->read;
    rev->log = c->log;
    rev->accept = 1;

#if (NGX_HAVE_DEFERRED_ACCEPT)
    rev->deferred_accept = ls->deferred_accept;
#endif

    rev->handler = ngx_event_accept;

    if (ngx_event_flags & NGX_USE_RTSIG_EVENT) {
        if (ngx_add_conn(c) == NGX_ERROR) {
            return NGX_ERROR;
        }

    } else {
        if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

