#include <from_ngx_src.h>
//#include <ngx_crc32.h>

static ngx_str_t err_levels[] = {
    ngx_null_string,
    ngx_string("emerg"),
    ngx_string("alert"),
    ngx_string("crit"),
    ngx_string("error"),
    ngx_string("warn"),
    ngx_string("notice"),
    ngx_string("info"),
    ngx_string("debug")
};

static const char *debug_levels[] = {
    "debug_core", "debug_alloc", "debug_mutex", "debug_event",
    "debug_http", "debug_mail", "debug_mysql"
};


ngx_log_t *
__ngx_log_create(ngx_cycle_t *cycle, ngx_str_t *name)
{
    ngx_log_t  *log;

    log = ngx_pcalloc(cycle->pool, sizeof(ngx_log_t));
    if (log == NULL) {
        return NULL;
    }

    log->file = ngx_conf_open_file(cycle, name);
    if (log->file == NULL) {
        return NULL;
    }

    return log;
}

char *
__ngx_log_set_levels(ngx_conf_t *cf, ngx_log_t *log)
{
    ngx_uint_t   i, n, d, found;
    ngx_str_t   *value;

    value = cf->args->elts;

    for (i = 2; i < cf->args->nelts; i++) {
        found = 0;

        for (n = 1; n <= NGX_LOG_DEBUG; n++) {
            if (ngx_strcmp(value[i].data, err_levels[n].data) == 0) {

                if (log->log_level != 0) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "duplicate log level \"%V\"",
                                       &value[i]);
                    return NGX_CONF_ERROR;
                }

                log->log_level = n;
                found = 1;
                break;
            }
        }

        for (n = 0, d = NGX_LOG_DEBUG_FIRST; d <= NGX_LOG_DEBUG_LAST; d <<= 1) {
            if (ngx_strcmp(value[i].data, debug_levels[n++]) == 0) {
                if (log->log_level & ~NGX_LOG_DEBUG_ALL) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "invalid log level \"%V\"",
                                       &value[i]);
                    return NGX_CONF_ERROR;
                }

                log->log_level |= d;
                found = 1;
                break;
            }
        }


        if (!found) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid log level \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }
    }

    if (log->log_level == NGX_LOG_DEBUG) {
        log->log_level = NGX_LOG_DEBUG_ALL;
    }

    return NGX_CONF_OK;
}


//void
//__ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
//    const char *fmt, ...)
//{
//    va_list  args;
//    u_char  *p, *last, *msg;
//    u_char   errstr[NGX_MAX_ERROR_STR];
//
//    if (log->file->fd == NGX_INVALID_FILE) {
//        return;
//    }
//
//    last = errstr + NGX_MAX_ERROR_STR;
//
//    ngx_memcpy(errstr, ngx_cached_err_log_time.data,
//               ngx_cached_err_log_time.len);
//
//    p = errstr + ngx_cached_err_log_time.len;
//
//    p = ngx_slprintf(p, last, " [%V] ", &err_levels[level]);
//
//    /* pid#tid */
//    p = ngx_slprintf(p, last, "%P#" NGX_TID_T_FMT ": ",
//                    ngx_log_pid, ngx_log_tid);
//
//    if (log->connection) {
//        p = ngx_slprintf(p, last, "*%uA ", log->connection);
//    }
//
//    msg = p;
//
//    va_start(args, fmt);
//    p = ngx_vslprintf(p, last, fmt, args);
//    va_end(args);
//
//    if (err) {
//        p = ngx_log_errno(p, last, err);
//    }
//
//    if (level != NGX_LOG_DEBUG && log->handler) {
//        p = log->handler(log, p, last - p);
//    }
//
//    if (p > last - NGX_LINEFEED_SIZE) {
//        p = last - NGX_LINEFEED_SIZE;
//    }
//
//    ngx_linefeed(p);
//
//    (void) ngx_write_fd(log->file->fd, errstr, p - errstr);
//
//    if (!ngx_use_stderr
//        || level > NGX_LOG_WARN
//        || log->file->fd == ngx_stderr)
//    {
//        return;
//    }
//
//    msg -= (7 + err_levels[level].len + 3);
//
//    (void) ngx_sprintf(msg, "nginx: [%V] ", &err_levels[level]);
//
//    (void) ngx_write_console(ngx_stderr, msg, p - msg);
//}

uint32_t
__ngx_crc32_long(u_char *p, size_t len)
{
    uint32_t  crc;

    crc = 0xffffffff;

    while (len--) {
        crc = ngx_crc32_table256[(crc ^ *p++) & 0xff] ^ (crc >> 8);
    }

    return crc ^ 0xffffffff;
}

uint32_t 
__ngx_crc32_init(uint32_t *crc)
{
    *crc = 0xffffffff;

    return *crc;
}

void
__ngx_crc32_update(uint32_t *crc, u_char *p, size_t len)
{
    uint32_t  c;

    c = *crc;

    while (len--) {
        c = ngx_crc32_table256[(c ^ *p++) & 0xff] ^ (c >> 8);
    }

    *crc = c;
}

uint32_t 
__ngx_crc32_final(uint32_t *crc)
{
    *crc ^= 0xffffffff;

    return *crc;
}

