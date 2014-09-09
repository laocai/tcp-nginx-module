
#ifndef _NGX_TCP_EXPORT_DATA_H_
#define _NGX_TCP_EXPORT_DATA_H_

#include <ngx_tcp_export_type.h>

/* sizeof(struct sockaddr_un) less than 255 */
#define MAX_UNIX_URL_LEN 255
typedef struct {
  u_char     len;
  u_char     unix_url[MAX_UNIX_URL_LEN];
} unix_listening_info_t;

typedef void *socketfd_info_tag;
typedef struct {
    /* Work process unix-listening info index. 
     * The index value is from ngx_process_slot. 
     */
    ngx_tcp_int_t        listening_unix_info_i;
    pid_t                pid;
    socketfd_info_tag    tag;
} socketfd_info_t;

/* All the address is in shared memory. */
typedef struct {
    /* Array of socketfd_info_t. Array index is socketfd. */
    socketfd_info_t        *socketfd_info;
    /* Array of unix listening info. */
    unix_listening_info_t  *listening_unix_info;
} socketfd_shm_info_t;

struct ngx_tcp_process_info_s {
    pid_t            pid;
    ngx_tcp_int_t    process_slot;
    ngx_tcp_int_t    worker_processes;
};
typedef struct ngx_tcp_process_info_s ngx_tcp_process_info_t;

typedef struct {
    ngx_tcp_process_info_t    *process_info;
    volatile uintptr_t        *current_msec;
    socketfd_shm_info_t       *socketfd_shm_info;
} ngx_tcp_export_data_t;

#endif

