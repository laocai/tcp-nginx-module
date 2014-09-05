#ifndef _FROM_NGX_SRC_H_
#define _FROM_NGX_SRC_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_log.h>

ngx_log_t *__ngx_log_create(ngx_cycle_t *cycle, ngx_str_t *name);
char *__ngx_log_set_levels(ngx_conf_t *cf, ngx_log_t *log);
//void __ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
//    const char *fmt, ...);

uint32_t __ngx_crc32_long(u_char *p, size_t len);

uint32_t __ngx_crc32_init(uint32_t *crc);
void __ngx_crc32_update(uint32_t *crc, u_char *p, size_t len);
uint32_t __ngx_crc32_final(uint32_t *crc);


#endif

