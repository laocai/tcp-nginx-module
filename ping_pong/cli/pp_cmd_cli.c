#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../../ngx_tcp_cmdso.h"
 
#define BUF_LEN 1024
#define PP_MSG "PP Cmd Ping Pong Msg"
#define PP_MSG_LEN (sizeof(PP_MSG) - 1)

static int write_n(int fd, const char *buf, int n);
static int read_n(int fd, char *buf, int n);

int 
main(void)
{
    int     n;
    int     fd;
    int     msg_len;
    char    send_buf[BUF_LEN];
    char    recv_buf[BUF_LEN];
    struct  sockaddr_in serv_addr;
    ngx_tcp_cmd_pkghead_t  *pkg_head;

    if((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror ("Create socket");
        return -1;
    }
 
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(9190);
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
 
    if(connect(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror ("Connect");
        return -1;
    }

    msg_len = PP_MSG_LEN + CMD_SESSION_PKG_HEAD_LEN;
    memset(send_buf, 0, BUF_LEN);
    pkg_head = (ngx_tcp_cmd_pkghead_t *) send_buf;
    pkg_head->size = msg_len;
    pkg_head->cmd = 100;
    ngx_tcp_cmd_pkghead_hton(pkg_head);
    memcpy(send_buf + CMD_SESSION_PKG_HEAD_LEN, PP_MSG, PP_MSG_LEN);

    while (1) {
        if (write_n(fd, send_buf, msg_len) == -1) {
            break;
        }
        memset(recv_buf, 0, BUF_LEN);
        if (read_n(fd, recv_buf, msg_len) == -1) {
            break;
        }
        pkg_head = (ngx_tcp_cmd_pkghead_t *) recv_buf;
        ngx_tcp_cmd_pkghead_ntoh(pkg_head);
        printf("main recv msg|msg_len=%d, msg_cmd=%d, msg=%s\n", 
               pkg_head->size, pkg_head->cmd, recv_buf + CMD_SESSION_PKG_HEAD_LEN);
    }

    return 0;
}

int 
write_n(int fd, const char *buf, int n)
{
    int writed = 0;
    int ret;

    while (n > writed) {
        ret = write(fd, buf + writed, n - writed);
        if (ret == -1) {
            perror ("write_n|write");
            return -1;
        }
        writed += ret;
    }

    return 0;
}

int 
read_n(int fd, char *buf, int n)
{
    int readed = 0;
    int ret;

    while (n > readed) {
        ret = read(fd, buf + readed, n - readed);
        if (ret == -1) {
            perror ("read_n|read");
            return -1;
        }
        readed += ret;
    }

    return 0;
}
