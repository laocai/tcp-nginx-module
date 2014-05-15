tcp-nginx-module
================

Use nginx as a common TCP server framework

<h3>Description</h3>

<p>The motivation for writing these is to use nginx as a common TCP server framework, So it called ngx<em>tcp.The ngx</em>tcp.jpg illustrates this framework.Most of the code is modificationed from nginx mail modules.I developed an application protocol that is named command protocol over the TCP. <br />
Command Protocol Format</p>

<pre><code>
    0                 1                   2                   3    
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            size                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            cmd                                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           spare0                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           spare1                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           spare2                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           spare3                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           spare4                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           spare5                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            body                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
</code></pre>

<p>Command Protocol Header Filed “size == head + body”</p>

<h3>Develop Command Protocol Server</h3>

<pre><code>example in the ping_pong dir
</code></pre>

<h3>Synopsis</h3>

<pre><code>tcp {
    max_socketfd_value          100000;
    worker_process_unix_listen  logs/tcp;
    # keys_zone size must &gt;= (max_socketfd_value * 16 + worker_processes * 512)
    socketfd_shm                /tmp/socketfd_shm keys_zone=cache_socketfd_shm:2m;
    max_pkg_size 2m;
    # error_log logs/tcp_err.log debug;
    server {
        timeout 240;
        protocol cmd;
        listen 9190;
    }
}
</code></pre>

<h3>Installation And Test</h3>

<pre><code>Download the latest stable version of the release tarball of this module
from github ()

Grab the nginx source code from nginx.org (&lt;http://nginx.org/&gt;), extract the source and go into the dir.

    # ./configure --prefix=/path/to/$build_prefix --add-module=/path/to/tcp_module
    # make
    # make install
    # mkdir /path/to/$build_prefix/cmdso
    # cd /path/to/tcp_module/ping_pong
    # make
    # cp  /path/to/tcp_module/ping_pong/svr/pp.so /path/to/$build_prefix/cmdso/
    # cd /path/to/$build_prefix/sbin/
    # ./nginx
    # cd /path/to/tcp_module/ping_pong/cli/
    # ./pp_cmd_cli
</code></pre>

<h3>FIXME</h3>

<pre><code>*   How to support nginx reload in ngx_tcp
*   Only support linux
</code></pre>

<h3>TODO</h3>

<pre><code>1.   test ssl 
2.   exploit more nginx/ngx_tcp to develop Command Protocol Shared Dynamic Library, for example shared memory and so on.
3.   add doc or blob
</code></pre>
