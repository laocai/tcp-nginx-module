
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_tcp.h>


static char *ngx_tcp_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_tcp_add_ports(ngx_conf_t *cf, ngx_array_t *ports,
    ngx_tcp_listen_t *listen);
static char *ngx_tcp_optimize_servers(ngx_conf_t *cf, ngx_array_t *ports);
static ngx_int_t ngx_tcp_add_addrs(ngx_conf_t *cf, ngx_tcp_port_t *mport,
    ngx_tcp_conf_addr_t *addr);
#if (NGX_HAVE_INET6)
static ngx_int_t ngx_tcp_add_addrs6(ngx_conf_t *cf, ngx_tcp_port_t *mport,
    ngx_tcp_conf_addr_t *addr);
#endif
static ngx_int_t ngx_tcp_cmp_conf_addrs(const void *one, const void *two);


ngx_uint_t  ngx_tcp_max_module;


static ngx_command_t  ngx_tcp_commands[] = {

    { ngx_string("tcp"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_tcp_block,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_tcp_module_ctx = {
    ngx_string("tcp"),
    NULL,
    NULL
};


ngx_module_t  ngx_tcp_module = {
    NGX_MODULE_V1,
    &ngx_tcp_module_ctx,               /* module context */
    ngx_tcp_commands,                  /* module directives */
    NGX_CORE_MODULE,                   /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    NULL,                              /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
ngx_tcp_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                        *rv;
    ngx_uint_t                   i, m, mi, s;
    ngx_conf_t                   pcf;
    ngx_array_t                  ports;
    ngx_tcp_listen_t           *listen;
    ngx_tcp_module_t           *module;
    ngx_tcp_conf_ctx_t         *ctx;
    ngx_tcp_core_srv_conf_t   **cscfp;
    ngx_tcp_core_main_conf_t   *cmcf;

    if (cmd->name.data[0] == 'i') {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "the \"imap\" directive is deprecated, "
                           "use the \"tcp\" directive instead");
    }

    /* the main tcp context */

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    *(ngx_tcp_conf_ctx_t **) conf = ctx;

    /* count the number of the http modules and set up their indices */

    ngx_tcp_max_module = 0;
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_TCP_MODULE) {
            continue;
        }

        ngx_modules[m]->ctx_index = ngx_tcp_max_module++;
    }


    /* the tcp main_conf context, it is the same in the all tcp contexts */

    ctx->main_conf = ngx_pcalloc(cf->pool,
                                 sizeof(void *) * ngx_tcp_max_module);
    if (ctx->main_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * the tcp null srv_conf context, it is used to merge
     * the server{}s' srv_conf's
     */

    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_tcp_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * create the main_conf's, the null srv_conf's, and the null loc_conf's
     * of the all tcp modules
     */

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_TCP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        mi = ngx_modules[m]->ctx_index;

        if (module->create_main_conf) {
            ctx->main_conf[mi] = module->create_main_conf(cf);
            if (ctx->main_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (module->create_srv_conf) {
            ctx->srv_conf[mi] = module->create_srv_conf(cf);
            if (ctx->srv_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }


    /* parse inside the tcp{} block */

    pcf = *cf;
    cf->ctx = ctx;

    cf->module_type = NGX_TCP_MODULE;
    cf->cmd_type = NGX_TCP_MAIN_CONF;
    rv = ngx_conf_parse(cf, NULL);

    if (rv != NGX_CONF_OK) {
        *cf = pcf;
        return rv;
    }


    /* init tcp{} main_conf's, merge the server{}s' srv_conf's */

    cmcf = ctx->main_conf[ngx_tcp_core_module.ctx_index];
    cscfp = cmcf->servers.elts;

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_TCP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        mi = ngx_modules[m]->ctx_index;

        /* init tcp{} main_conf's */

        cf->ctx = ctx;

        if (module->init_main_conf) {
            rv = module->init_main_conf(cf, ctx->main_conf[mi]);
            if (rv != NGX_CONF_OK) {
                *cf = pcf;
                return rv;
            }
        }

        for (s = 0; s < cmcf->servers.nelts; s++) {

            /* merge the server{}s' srv_conf's */

            cf->ctx = cscfp[s]->ctx;

            if (module->merge_srv_conf) {
                rv = module->merge_srv_conf(cf,
                                            ctx->srv_conf[mi],
                                            cscfp[s]->ctx->srv_conf[mi]);
                if (rv != NGX_CONF_OK) {
                    *cf = pcf;
                    return rv;
                }
            }
        }
    }

    *cf = pcf;


    if (ngx_array_init(&ports, cf->temp_pool, 4, sizeof(ngx_tcp_conf_port_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    listen = cmcf->listen.elts;

    for (i = 0; i < cmcf->listen.nelts; i++) {
        if (ngx_tcp_add_ports(cf, &ports, &listen[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return ngx_tcp_optimize_servers(cf, &ports);
}


static ngx_int_t
ngx_tcp_add_ports(ngx_conf_t *cf, ngx_array_t *ports,
    ngx_tcp_listen_t *listen)
{
    in_port_t              p;
    ngx_uint_t             i;
    struct sockaddr       *sa;
    struct sockaddr_in    *sin;
    ngx_tcp_conf_port_t  *port;
    ngx_tcp_conf_addr_t  *addr;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6   *sin6;
#endif

    sa = (struct sockaddr *) &listen->sockaddr;

    switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) sa;
        p = sin6->sin6_port;
        break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        p = 0;
        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) sa;
        p = sin->sin_port;
        break;
    }

    port = ports->elts;
    for (i = 0; i < ports->nelts; i++) {
        if (p == port[i].port && sa->sa_family == port[i].family) {

            /* a port is already in the port list */

            port = &port[i];
            goto found;
        }
    }

    /* add a port to the port list */

    port = ngx_array_push(ports);
    if (port == NULL) {
        return NGX_ERROR;
    }

    port->family = sa->sa_family;
    port->port = p;

    if (ngx_array_init(&port->addrs, cf->temp_pool, 2,
                       sizeof(ngx_tcp_conf_addr_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

found:

    addr = ngx_array_push(&port->addrs);
    if (addr == NULL) {
        return NGX_ERROR;
    }

    addr->sockaddr = (struct sockaddr *) &listen->sockaddr;
    addr->socklen = listen->socklen;
    addr->ctx = listen->ctx;
    addr->bind = listen->bind;
    addr->wildcard = listen->wildcard;
    addr->so_keepalive = listen->so_keepalive;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    addr->tcp_keepidle = listen->tcp_keepidle;
    addr->tcp_keepintvl = listen->tcp_keepintvl;
    addr->tcp_keepcnt = listen->tcp_keepcnt;
#endif
#if (NGX_TCP_SSL)
    addr->ssl = listen->ssl;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    addr->ipv6only = listen->ipv6only;
#endif

    return NGX_OK;
}


static char *
ngx_tcp_optimize_servers(ngx_conf_t *cf, ngx_array_t *ports)
{
    ngx_uint_t             i, p, last, bind_wildcard;
    ngx_listening_t       *ls;
    ngx_tcp_port_t       *mport;
    ngx_tcp_conf_port_t  *port;
    ngx_tcp_conf_addr_t  *addr;

    port = ports->elts;
    for (p = 0; p < ports->nelts; p++) {

        ngx_sort(port[p].addrs.elts, (size_t) port[p].addrs.nelts,
                 sizeof(ngx_tcp_conf_addr_t), ngx_tcp_cmp_conf_addrs);

        addr = port[p].addrs.elts;
        last = port[p].addrs.nelts;

        /*
         * if there is the binding to the "*:port" then we need to bind()
         * to the "*:port" only and ignore the other bindings
         */

        if (addr[last - 1].wildcard) {
            addr[last - 1].bind = 1;
            bind_wildcard = 1;

        } else {
            bind_wildcard = 0;
        }

        i = 0;

        while (i < last) {

            ngx_tcp_core_main_conf_t *cmcf;
            ngx_tcp_core_srv_conf_t  *cscf;

            if (bind_wildcard && !addr[i].bind) {
                i++;
                continue;
            }
            cmcf = addr[i].ctx->main_conf[ngx_tcp_core_module.ctx_index];
            cscf = addr[i].ctx->srv_conf[ngx_tcp_core_module.ctx_index];

            ls = ngx_create_listening(cf, addr[i].sockaddr, addr[i].socklen);
            if (ls == NULL) {
                return NGX_CONF_ERROR;
            }

            ls->addr_ntop = 1;
            ls->handler = ngx_tcp_init_connection;
            ls->pool_size = cscf->connection_pool_size;

            if (cmcf->error_log == NULL) {
                ls->logp = &cf->cycle->new_log;
            } else {
                ls->logp = cmcf->error_log;
            }
            ls->log.data = &ls->addr_text;
            ls->log.handler = ngx_accept_log_error;

            ls->keepalive = addr[i].so_keepalive;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
            ls->keepidle = addr[i].tcp_keepidle;
            ls->keepintvl = addr[i].tcp_keepintvl;
            ls->keepcnt = addr[i].tcp_keepcnt;
#endif

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
            ls->ipv6only = addr[i].ipv6only;
#endif

            mport = ngx_palloc(cf->pool, sizeof(ngx_tcp_port_t));
            if (mport == NULL) {
                return NGX_CONF_ERROR;
            }

            ls->servers = mport;

            if (i == last - 1) {
                mport->naddrs = last;

            } else {
                mport->naddrs = 1;
                i = 0;
            }

            switch (ls->sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
            case AF_INET6:
                if (ngx_tcp_add_addrs6(cf, mport, addr) != NGX_OK) {
                    return NGX_CONF_ERROR;
                }
                break;
#endif
            default: /* AF_INET */
                if (ngx_tcp_add_addrs(cf, mport, addr) != NGX_OK) {
                    return NGX_CONF_ERROR;
                }
                break;
            }

            addr++;
            last--;
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_tcp_add_addrs(ngx_conf_t *cf, ngx_tcp_port_t *mport,
    ngx_tcp_conf_addr_t *addr)
{
    u_char              *p;
    size_t               len;
    ngx_uint_t           i;
    ngx_tcp_in_addr_t  *addrs;
    struct sockaddr_in  *sin;
    u_char               buf[NGX_SOCKADDR_STRLEN];

    mport->addrs = ngx_pcalloc(cf->pool,
                               mport->naddrs * sizeof(ngx_tcp_in_addr_t));
    if (mport->addrs == NULL) {
        return NGX_ERROR;
    }

    addrs = mport->addrs;

    for (i = 0; i < mport->naddrs; i++) {

        sin = (struct sockaddr_in *) addr[i].sockaddr;
        addrs[i].addr = sin->sin_addr.s_addr;

        addrs[i].conf.ctx = addr[i].ctx;
#if (NGX_TCP_SSL)
        addrs[i].conf.ssl = addr[i].ssl;
#endif

        len = ngx_sock_ntop(addr[i].sockaddr, buf, NGX_SOCKADDR_STRLEN, 1);

        p = ngx_pnalloc(cf->pool, len);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(p, buf, len);

        addrs[i].conf.addr_text.len = len;
        addrs[i].conf.addr_text.data = p;
    }

    return NGX_OK;
}


#if (NGX_HAVE_INET6)

static ngx_int_t
ngx_tcp_add_addrs6(ngx_conf_t *cf, ngx_tcp_port_t *mport,
    ngx_tcp_conf_addr_t *addr)
{
    u_char               *p;
    size_t                len;
    ngx_uint_t            i;
    ngx_tcp_in6_addr_t  *addrs6;
    struct sockaddr_in6  *sin6;
    u_char                buf[NGX_SOCKADDR_STRLEN];

    mport->addrs = ngx_pcalloc(cf->pool,
                               mport->naddrs * sizeof(ngx_tcp_in6_addr_t));
    if (mport->addrs == NULL) {
        return NGX_ERROR;
    }

    addrs6 = mport->addrs;

    for (i = 0; i < mport->naddrs; i++) {

        sin6 = (struct sockaddr_in6 *) addr[i].sockaddr;
        addrs6[i].addr6 = sin6->sin6_addr;

        addrs6[i].conf.ctx = addr[i].ctx;
#if (NGX_TCP_SSL)
        addrs6[i].conf.ssl = addr[i].ssl;
#endif

        len = ngx_sock_ntop(addr[i].sockaddr, buf, NGX_SOCKADDR_STRLEN, 1);

        p = ngx_pnalloc(cf->pool, len);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(p, buf, len);

        addrs6[i].conf.addr_text.len = len;
        addrs6[i].conf.addr_text.data = p;
    }

    return NGX_OK;
}

#endif


static ngx_int_t
ngx_tcp_cmp_conf_addrs(const void *one, const void *two)
{
    ngx_tcp_conf_addr_t  *first, *second;

    first = (ngx_tcp_conf_addr_t *) one;
    second = (ngx_tcp_conf_addr_t *) two;

    if (first->wildcard) {
        /* a wildcard must be the last resort, shift it to the end */
        return 1;
    }

    if (second->wildcard) {
        /* a wildcard must be the last resort, shift it to the end */
        return -1;
    }

    if (first->bind && !second->bind) {
        /* shift explicit bind()ed addresses to the start */
        return -1;
    }

    if (!first->bind && second->bind) {
        /* shift explicit bind()ed addresses to the start */
        return 1;
    }

    /* do not sort by default */

    return 0;
}

ngx_tcp_session_t *
ngx_tcp_create_session(ngx_connection_t *c)
{
    return ngx_pcalloc(c->pool, sizeof(ngx_tcp_session_t));
}

ngx_chain_t *
ngx_tcp_chain_get_free_buf(ngx_tcp_output_chain_ctx_t *ctx, size_t total_size)
{
    ngx_chain_t *cl, **ll;
    size_t size = 0;

    cl = NULL;
    ll = &cl;
    while (size < total_size) {
        *ll = ngx_chain_get_free_buf(ctx->pool, &ctx->free);
        if (*ll == NULL) {
            goto failed;
        }
        if (NULL == (*ll)->buf->start) {
            size_t buf_size = total_size - size;
            (*ll)->buf->start = ngx_palloc(ctx->pool, buf_size);
            if (NULL == (*ll)->buf->start) {
                goto failed;
            }
            (*ll)->buf->pos = (*ll)->buf->start;
            (*ll)->buf->last = (*ll)->buf->start;
            (*ll)->buf->end = (*ll)->buf->start + buf_size;
            (*ll)->buf->temporary = 1;
        }
        size += (*ll)->buf->end - (*ll)->buf->last;
        (*ll)->next = NULL;
        ll = &(*ll)->next;
    }

    return cl;

failed:
    if (cl != NULL)
        ngx_chain_update_chains(ctx->pool, &ctx->free, &ctx->busy, &cl, ctx->tag);
    return NULL;
}


ngx_int_t 
ngx_tcp_open_listening_socket(ngx_listening_t  *ls)
{
    int               reuseaddr;
    ngx_uint_t        tries, failed;
    ngx_err_t         err;
    ngx_log_t        *log;
    ngx_socket_t      s;

    reuseaddr = 1;
    log = ls->logp;

    for (tries = 5; tries; tries--) {
        failed = 0;

        if (ls->ignore) {
            continue;
        }

        if (ls->fd != -1) {
            break;
        }

        s = ngx_socket(ls->sockaddr->sa_family, ls->type, 0);

        if (s == -1) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                          ngx_socket_n " %V failed", &ls->addr_text);
            return NGX_ERROR;
        }

        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                       (const void *) &reuseaddr, sizeof(int))
            == -1)
        {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                          "setsockopt(SO_REUSEADDR) %V failed",
                          &ls->addr_text);

            if (ngx_close_socket(s) == -1) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                              ngx_close_socket_n " %V failed",
                              &ls->addr_text);
            }

            return NGX_ERROR;
        }

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)

        if (ls->sockaddr->sa_family == AF_INET6) {
            int  ipv6only;

            ipv6only = ls->ipv6only;

            if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY,
                           (const void *) &ipv6only, sizeof(int))
                == -1)
            {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                              "setsockopt(IPV6_V6ONLY) %V failed, ignored",
                              &ls->addr_text);
            }
        }
#endif
            /* TODO: close on exit */

        if (!(ngx_event_flags & NGX_USE_AIO_EVENT)) {
            if (ngx_nonblocking(s) == -1) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                              ngx_nonblocking_n " %V failed",
                              &ls->addr_text);

                if (ngx_close_socket(s) == -1) {
                    ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                                  ngx_close_socket_n " %V failed",
                                  &ls->addr_text);
                }

                return NGX_ERROR;
            }
        }

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, log, 0,
                       "bind() %V #%d ", &ls->addr_text, s);

#if (NGX_HAVE_UNIX_DOMAIN)
        {
            u_char  *name;
            name = ls->addr_text.data + sizeof("unix:") - 1;
            unlink((const char *)name);
        }
#endif

        if (bind(s, ls->sockaddr, ls->socklen) == -1) {
            err = ngx_socket_errno;

            if (err == NGX_EADDRINUSE && ngx_test_config) {
                continue;
            }

            ngx_log_error(NGX_LOG_EMERG, log, err,
                          "bind() to %V failed", &ls->addr_text);

            if (ngx_close_socket(s) == -1) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                              ngx_close_socket_n " %V failed",
                              &ls->addr_text);
            }

            if (err != NGX_EADDRINUSE) {
                return NGX_ERROR;
            }

            failed = 1;

            break;
        }

#if (NGX_HAVE_UNIX_DOMAIN)

        if (ls->sockaddr->sa_family == AF_UNIX) {
            mode_t   mode;
            u_char  *name;

            name = ls->addr_text.data + sizeof("unix:") - 1;
            mode = (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);

            if (chmod((char *) name, mode) == -1) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                              "chmod() \"%s\" failed", name);
            }

            if (ngx_test_config) {
                if (ngx_delete_file(name) == NGX_FILE_ERROR) {
                    ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                                  ngx_delete_file_n " %s failed", name);
                }
            }
        }
#endif

        if (listen(s, ls->backlog) == -1) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                          "listen() to %V, backlog %d failed",
                          &ls->addr_text, ls->backlog);

            if (ngx_close_socket(s) == -1) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                              ngx_close_socket_n " %V failed",
                              &ls->addr_text);
            }

            return NGX_ERROR;
        }

        ls->listen = 1;

        ls->fd = s;

        if (!failed) {
            break;
        }

        /* TODO: delay configurable */

        ngx_log_error(NGX_LOG_NOTICE, log, 0,
                      "try again to bind() after 500ms");

        ngx_msleep(500);
    }

    if (failed) {
        ngx_log_error(NGX_LOG_EMERG, log, 0, "still could not bind()");
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
//ngx_tcp_chain_writer(void *data, ngx_chain_t *in)
ngx_tcp_chain_writer(ngx_tcp_session_t *s)
{
    //s->output_ctx->filter_ctx, 
    //s->output_buffer_chain
    ngx_chain_writer_ctx_t *ctx;
    ngx_chain_t            *in;
    ngx_tcp_output_again_t *again_ptr;

    off_t                  size;
    ngx_chain_t            *cl;
    ngx_connection_t       *c;
  
    ctx = s->output_ctx->filter_ctx;
    in = s->output_buffer_chain;
    again_ptr = &s->output_again;
    c = ctx->connection;
    
    again_ptr->out_chain_arr[again_ptr->ix_w++] = in;
    again_ptr->ix_w &= (OUTPUT_CHAIN_AGAIN_SIZE - 1);
    
    //if output_again_arr is full, return error;
    if (again_ptr->ix_w == again_ptr->ix_r) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, 
            "ngx_tcp_chain_writer|output_again_arr is full|ix_w=%d|ix_r=%d", 
            again_ptr->ix_w, again_ptr->ix_r);
        return NGX_ERROR;
    }
  
    while (1) {
        if (NULL == again_ptr->out_chain_arr[again_ptr->ix_r]) {
        //  ix_r = 0;
        //  ix_w = 0;
            break;
        }
       
        ctx->out = again_ptr->out_chain_arr[again_ptr->ix_r];

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
            "tcp chain writer in: %p", ctx->out);

        size = 0;
        for (cl = ctx->out; cl; cl = cl->next) {

    #if 1
            if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
                ngx_debug_point();
            }

    #endif

            size += ngx_buf_size(cl->buf);
        }

        if (size == 0 && !c->buffered) {
            again_ptr->out_chain_arr[again_ptr->ix_r] = NULL;
            again_ptr->ix_r++;
            again_ptr->ix_r &= (OUTPUT_CHAIN_AGAIN_SIZE - 1);
            continue;
        }

        again_ptr->out_chain_arr[again_ptr->ix_r] = 
            c->send_chain(c, 
                again_ptr->out_chain_arr[again_ptr->ix_r], ctx->limit);
        
        ctx->out = again_ptr->out_chain_arr[again_ptr->ix_r];
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                       "chain writer out: %p", ctx->out);

        if (ctx->out == NGX_CHAIN_ERROR) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, 
                "ngx_tcp_chain_writer|out_chain_arr[%d]==NGX_CHAIN_ERROR", 
                again_ptr->ix_r);
            again_ptr->out_chain_arr[again_ptr->ix_r] = NULL;
            again_ptr->ix_r++;
            again_ptr->ix_r &= (OUTPUT_CHAIN_AGAIN_SIZE - 1);
            return NGX_ERROR;
        }

        if (ctx->out == NULL) {
            ctx->last = &ctx->out;
            
            if (!c->buffered) {
                again_ptr->ix_r++;
                again_ptr->ix_r &= (OUTPUT_CHAIN_AGAIN_SIZE - 1);
                //return NGX_OK;
                continue;
            }
        }
        
        ngx_log_error(NGX_LOG_DEBUG, c->log, 0,
            "ngx_tcp_chain_writer|again_ptr->out_chain_arr[%d] NGX_AGAIN", 
            again_ptr->ix_r);
        return NGX_AGAIN;
    }
    return NGX_OK;    
}
