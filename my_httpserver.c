#include "version.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <limits.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <time.h>
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dirent.h>

#include "port.h"
#include "match.h"
#include "tdate_parse.h"

/**
gcc my_httpserver.c tdate_parse.c match.c -o my_http -I ./
**/

#ifdef HAVE_SENDFILE
# ifdef HAVE_LINUX_SENDFILE
#  include <sys/sendfile.h>
# else /* HAVE_LINUX_SENDFILE */
#  include <sys/uio.h>
# endif /* HAVE_LINUX_SENDFILE */
#endif /* HAVE_SENDFILE */

#ifndef DEFAULT_USER
#define DEFAULT_USER "nobody"
#endif /*DEFAULT_USER*/

#ifndef DEFAULT_HTTP_PORT
#define DEFAULT_HTTP_PORT 80
#endif /*DEFAULT_HTTP_PORT*/

#ifndef READ_TIMEOUT
#define READ_TIMEOUT 60
#endif /* READ_TIMEOUT */

#ifndef WRITE_TIMEOUT
#define WRITE_TIMEOUT 300
#endif /* WRITE_TIMEOUT */

#ifndef ERR_DIR
#define ERR_DIR "errors"
#endif /* ERR_DIR */

#ifndef AUTH_FILE
#define AUTH_FILE ".htpasswd"
#endif /* AUTH_FILE */

#ifndef DEFAULT_CHARSET
#define DEFAULT_CHARSET "iso-8859-1"
#endif /* DEFAULT_CHARSET */

#ifndef SIZE_T_MAX
#define SIZE_T_MAX 2147483647L
#endif

#define METHOD_UNKNOWN 0
#define METHOD_GET 1
#define METHOD_HEAD 2
#define METHOD_POST 3

typedef union{
	struct sockaddr sa;
	struct sockaddr_in sa_in;
}usockaddr;

struct mime_entry{
	char* ext;
	size_t ext_len;
	char* val;
	size_t val_len;
};

static char* argv0;
static int debug;
static int port;
static char* hostname;
static char* user;
static char* remoteuser;
static char hostname_buf[500];
static int listen4_fd;
static char cwd[MAXPATHLEN];
static int conn_fd;
static usockaddr client_addr;
static char* request;
static size_t request_size, request_len, request_idx;
static int method;
static char* path;
static char* file;
static char* pathinfo;
static char* query;
static char* protocol;
static int status;
static off_t bytes;
static char* req_hostname;
static char* authorization;
static size_t content_length;
static char* content_type;
static char* cookie;
static char* host;
static time_t if_modified_since;
static char* referer;
static char* useragent;
static char* response;
static size_t response_size, response_len;
static int max_age;
static int vhost;
static char* charset;

struct stat sb;


static void init_mime(void);
static void handle_request(void);
static void handle_read_timeout(int sig);
static void handle_write_timeout(int sig);
static void handle_sigchld( int sig );
static void handle_sigterm( int sig );
static void handle_sighup( int sig );
static char* ntoa( usockaddr* usaP );
static void* e_malloc( size_t size );
static void* e_realloc( void* optr, size_t size );
static int sockaddr_check( usockaddr* usaP );
static size_t sockaddr_len( usockaddr* usaP );
static int initialize_listen_socket( usockaddr* usaP );
static void start_request(void);
static ssize_t my_read( char* buf, size_t size );
static ssize_t my_write( char* buf, size_t size );
static void add_to_request( char* str, size_t len );
static void add_to_buf( char** bufP, size_t* bufsizeP, size_t* buflenP, char* str, size_t len );
static char* get_request_line( void );
static void send_error( int s, char* title, char* extra_header, char* text );
static void add_headers( int s, char* title, char* extra_header, char* me, char* mt, off_t b, time_t mod );
static void start_response( void );
static void add_to_response( char* str, size_t len );
static void send_error_body( int s, char* title, char* text );
static int send_error_file( char* filename );
static void send_error_tail( void );
static void send_response( void );
static char* get_method_str( int m );
static void strdecode( char* to, char* from );
static int hexit(char c);
static void de_dotdot( char* file );
static char* virtual_file( char* file );
static int get_pathinfo( void );
static void do_file( void );
static void auth_check( char* dirname );
static const char* figure_mime( char* name, char* me, size_t me_size );
static void send_via_write( int fd, off_t size );

#ifdef HAVE_SENDFILE
static int my_sendfile( int fd, int socket, off_t offset, size_t nbytes );
#endif /* HAVE_SENDFILE */

#ifdef HAVE_SCANDIR
static char* file_details( const char* dir, const char* name );
static void strencode( char* to, size_t tosize, const char* from );
#endif /* HAVE_SCANDIR */

static void do_dir( void );

static struct mime_entry enc_tab[] = {
	{ "Z", 0, "compress", 0 },
	{ "gz", 0, "gzip", 0 },
	{ "uu", 0, "x-uuencode", 0 },
};

static const int n_enc_tab = sizeof(enc_tab) / sizeof(*enc_tab);
//the array must in order,to support binary search
static struct mime_entry typ_tab[] = {
	{ "a", 0, "application/octet-stream", 0 },
	{ "bin", 0, "application/octet-stream", 0 },
	{ "css", 0, "text/css", 0 },
	{ "exe", 0, "application/octet-stream", 0 },
 	{ "htm", 0, "text/html; charset=%s", 0 },
    { "html", 0, "text/html; charset=%s", 0 },
	{ "jpg", 0, "image/jpeg", 0 },
	{ "js", 0, "application/x-javascript", 0 },
	{ "mp3", 0, "audio/mpeg", 0 },
 	{ "mp4", 0, "video/mp4", 0 },
};

static const int n_typ_tab = sizeof(typ_tab) / sizeof(*typ_tab);
static int ext_compare(a, b)
	struct mime_entry* a;
	struct mime_entry* b;
	{
		return strcmp(a->ext, b->ext);
	}

static void handle_write_timeout( int sig )
{
	syslog( LOG_INFO, "%.80s connection timed out writing", ntoa( &client_addr ) );
	exit( 1 );
}

static void handle_sigchld( int sig )
{
	printf("handle_sigchld sig=%d\n", sig);
	const int oerrno = errno;
    pid_t pid;
    int status;

#ifndef HAVE_SIGSET
    /* Set up handler again. */
    (void) signal( SIGCHLD, handle_sigchld );
#endif /* ! HAVE_SIGSET */

    /* Reap defunct children until there aren't any more. */
    for (;;)
	{
#ifdef HAVE_WAITPID
		pid = waitpid( (pid_t) -1, &status, WNOHANG );
#else /* HAVE_WAITPID */
		pid = wait3( &status, WNOHANG, (struct rusage*) 0 );
#endif /* HAVE_WAITPID */
		if ( (int) pid == 0 )		/* none left */
	    	break;
		if ( (int) pid < 0 )
	    {
	    	if ( errno == EINTR || errno == EAGAIN )
			continue;
		    /* ECHILD shouldn't happen with the WNOHANG option,
		    ** but with some kernels it does anyway.  Ignore it.
		    */
		    if ( errno != ECHILD )
			{
				syslog( LOG_ERR, "child wait - %m" );
				perror( "child wait" );
			}
		    break;
	    }
	}

    /* Restore previous errno. */
    errno = oerrno;
}

static void handle_sigterm( int sig )
{
	printf("handle_sigterm sig=%d\n", sig);
	exit(1);
}

static void handle_sighup( int sig )
{
	printf("handle_sighup sig=%d\n", sig);
}

static char* ntoa( usockaddr* usaP )
{
#ifdef USE_IPV6
    static char str[200];

    if ( getnameinfo( &usaP->sa, sockaddr_len( usaP ), str, sizeof(str), 0, 0, NI_NUMERICHOST ) != 0 )
	{
		str[0] = '?';
		str[1] = '\0';
	}
    else if ( IN6_IS_ADDR_V4MAPPED( &usaP->sa_in6.sin6_addr ) && strncmp( str, "::ffff:", 7 ) == 0 )
		/* Elide IPv6ish prefix for IPv4 addresses. */
		(void) strcpy( str, &str[7] );

    return str;

#else /* USE_IPV6 */

    return inet_ntoa( usaP->sa_in.sin_addr );

#endif /* USE_IPV6 */
}

static void* e_malloc( size_t size )
{
	void* ptr;

	ptr = malloc( size );
	if ( ptr == (void*) 0 )
	{
		syslog( LOG_CRIT, "out of memory" );
		(void) fprintf( stderr, "%s: out of memory\n", argv0 );
		exit( 1 );
	}
	return ptr;
}

static void* e_realloc( void* optr, size_t size )
{
	void* ptr;

	ptr = realloc( optr, size );
	if ( ptr == (void*) 0 )
	{
		syslog( LOG_CRIT, "out of memory" );
		(void) fprintf( stderr, "%s: out of memory\n", argv0 );
		exit( 1 );
	}
	return ptr;
}

static int sockaddr_check( usockaddr* usaP )
{
	switch ( usaP->sa.sa_family )
	{
		case AF_INET: return 1;
		#ifdef USE_IPV6
		case AF_INET6: return 1;
		#endif /* USE_IPV6 */
		default:
		return 0;
	}
}

static size_t sockaddr_len( usockaddr* usaP )
{
	switch ( usaP->sa.sa_family )
	{
		case AF_INET: return sizeof(struct sockaddr_in);
		#ifdef USE_IPV6
		case AF_INET6: return sizeof(struct sockaddr_in6);
		#endif /* USE_IPV6 */
		default:
		return 0;	/* shouldn't happen */
	}
}

static int initialize_listen_socket( usockaddr* usaP )
{
	int listen_fd;
	int i;

	/* Check sockaddr. */
	if ( ! sockaddr_check( usaP ) )
	{
		syslog(
		    LOG_ERR, "unknown sockaddr family on listen socket - %d",
		    usaP->sa.sa_family );
		(void) fprintf(
		    stderr, "%s: unknown sockaddr family on listen socket - %d\n",
		    argv0, usaP->sa.sa_family );
		return -1;
	}

	listen_fd = socket( usaP->sa.sa_family, SOCK_STREAM, 0 );
	if ( listen_fd < 0 )
	{
		syslog( LOG_CRIT, "socket %.80s - %m", ntoa( usaP ) );
		perror( "socket" );
		return -1;
	}

	(void) fcntl( listen_fd, F_SETFD, 1 );

	i = 1;
	if ( setsockopt( listen_fd, SOL_SOCKET, SO_REUSEADDR, (void*) &i, sizeof(i) ) < 0 )
	{
		syslog( LOG_CRIT, "setsockopt SO_REUSEADDR - %m" );
		perror( "setsockopt SO_REUSEADDR" );
		return -1;
	}

	if ( bind( listen_fd, &usaP->sa, sockaddr_len( usaP ) ) < 0 )
	{
		syslog( LOG_CRIT, "bind %.80s - %m", ntoa( usaP ) );
		perror( "bind" );
		return -1;
	}

	if ( listen( listen_fd, 1024 ) < 0 )
	{
		syslog( LOG_CRIT, "listen - %m" );
		perror( "listen" );
		return -1;
	}

	#ifdef HAVE_ACCEPT_FILTERS
	{
		struct accept_filter_arg af;
		(void) bzero( &af, sizeof(af) );
		(void) strcpy( af.af_name, ACCEPT_FILTER_NAME );
		(void) setsockopt( listen_fd, SOL_SOCKET, SO_ACCEPTFILTER, (char*) &af, sizeof(af) );
	}
	#endif /* HAVE_ACCEPT_FILTERS */

	return listen_fd;
}

static void start_response( void )
{
	response_size = 0;
}

static int get_pathinfo( void )
{
	int r;
	pathinfo = &file[strlen(file)];
	for(;;){
		do{
			--pathinfo;
			if(pathinfo <= file){
				pathinfo = (char*)0;
				return -1;
			}
		}while(*pathinfo != '/');

		*pathinfo = '\0';
		r = stat(file, &sb);
		if(r >= 0){
			++pathinfo;
			return r;
		}else {
			*pathinfo = '/';
		}
	}
}

static void init_mime(void)
{
	int i;
	qsort(enc_tab, n_enc_tab, sizeof(*enc_tab), ext_compare);
	qsort(typ_tab, n_typ_tab, sizeof(*typ_tab), ext_compare);

	/* Fill in the lengths. */
    for ( i = 0; i < n_enc_tab; ++i )
	{
		enc_tab[i].ext_len = strlen( enc_tab[i].ext );
		enc_tab[i].val_len = strlen( enc_tab[i].val );
	}
    for ( i = 0; i < n_typ_tab; ++i )
	{
		typ_tab[i].ext_len = strlen( typ_tab[i].ext );
		typ_tab[i].val_len = strlen( typ_tab[i].val );
	}
}

static const char* figure_mime( char* name, char* me, size_t me_size )
{
	char* prev_dot;
	char* dot;
	char* ext;
	int me_indexes[100], n_me_indexes;
	size_t ext_len, me_len;
	int i, top, bot, mid;
	int r;
	const char* default_type = "text/plain; charset=%s";
	const char* type;

	n_me_indexes = 0;
	//name = "index.html"
	for(prev_dot = &name[strlen(name)]; ; prev_dot = dot){
		for(dot = prev_dot-1; dot >= name && *dot != '.'; --dot)
			;
		if(dot < name){ //如果没有扩展名
			type = default_type;
			goto done;
		}
		ext = dot + 1; //跳过'.'
		ext_len = prev_dot - ext;

		/* Search the encodings table.  Linear search is fine here, there
		** are only a few entries.
		*/
		for(i = 0; i < n_enc_tab; ++i){
			if(ext_len == enc_tab[i].ext_len && strncasecmp(ext, enc_tab[i].ext, ext_len) == 0){
				if(n_me_indexes < sizeof(me_indexes)/sizeof(*me_indexes)){
					me_indexes[n_me_indexes] = i;
					++n_me_indexes;
				}
				goto next;
			}
		}
		printf("No encoding extension found: %s\n", ext);
		break;

		next: ;
	}

	/* Binary search for a matching type extension. */
	top = n_typ_tab - 1;
	bot = 0;
	while(top >= bot){
		mid = (top + bot) / 2;
		r = strncasecmp(ext, typ_tab[mid].ext, ext_len);
		if(r < 0){
			top = mid - 1;
		}else if(r > 0){
			bot = mid + 1;
		}else{
			if(ext_len < typ_tab[mid].ext_len){
				top = mid - 1;
			}else if(ext_len > typ_tab[mid].ext_len){
				bot = mid + 1;
			}else{
				type = typ_tab[mid].val;
				goto done;
			}
		}
	}

	type = default_type;

	done: 
	/* The last thing we do is actually generate the mime-encoding header. */
	me[0] = '\0';
	me_len = 0;
	for( i = n_me_indexes - 1; i >= 0; --i){
		//normally this condition is met
		if(me_len + enc_tab[me_indexes[i]].val_len + 1 < me_size){
			if(me[0] != '\0'){
				strcpy(&me[me_len], ",");
				++me_len;
			}
			strcpy(&me[me_len], enc_tab[me_indexes[i]].val);
			me_len += enc_tab[me_indexes[i]].val_len;
		}
	}

	return type;
}

static int hexit(char c){
	if ( c >= '0' && c <= '9' )
		return c - '0';
    if ( c >= 'a' && c <= 'f' )
		return c - 'a' + 10;
    if ( c >= 'A' && c <= 'F' )
		return c - 'A' + 10;
    return 0;           /* shouldn't happen, we're guarded by isxdigit() */
}

static void de_dotdot( char* file )
{
	char* cp;
    char* cp2;
    int l;
    /*
    .///.//../../abc/../def/ok 合并所有连续的字符串'/'
    ././../../abc/../def/ok 去除所有以"./"开头的字符串
	../../abc/../def/ok     去除所有以"../"开头的字符串
	abc/../def/ok	去除字符串中的"/../"
	def/ok
    */
    /* Collapse any multiple / sequences. */
    while ( ( cp = strstr( file, "//") ) != (char*) 0 )
	{
		for ( cp2 = cp + 2; *cp2 == '/'; ++cp2 ) //hello///world//ok
	    	continue;
		(void) strcpy( cp + 1, cp2 );
	}

    /* Remove leading ./ and any /./ sequences. */
    while ( strncmp( file, "./", 2 ) == 0 )
		(void) strcpy( file, file + 2 );
    while ( ( cp = strstr( file, "/./") ) != (char*) 0 )
		(void) strcpy( cp, cp + 2 );

    /* Alternate between removing leading ../ and removing xxx/../ */
    for (;;)
	{
		while ( strncmp( file, "../", 3 ) == 0 )
		    (void) strcpy( file, file + 3 );
		cp = strstr( file, "/../" );
		if ( cp == (char*) 0 )
		    break;
		for ( cp2 = cp - 1; cp2 >= file && *cp2 != '/'; --cp2 )
		    continue;
		(void) strcpy( cp2 + 1, cp + 4 );
	}

    /* Also elide any xxx/.. at the end. */
    while ( ( l = strlen( file ) ) > 3 &&
	    strcmp( ( cp = file + l - 3 ), "/.." ) == 0 )
	{
		for ( cp2 = cp - 1; cp2 >= file && *cp2 != '/'; --cp2 )
	    	continue;
		if ( cp2 < file )
	   	break;
		*cp2 = '\0';
	}
}

static char* virtual_file( char* file )
{
	printf("file =%s\n", file);
    char* cp;
    static char vfile[10000];

    /* Use the request's hostname, or fall back on the IP address. */
    if ( host != (char*) 0 ){
		req_hostname = host;
    }else{
		usockaddr usa;
		int sz = sizeof(usa);
		if ( getsockname( conn_fd, &usa.sa, &sz ) < 0 ){
		    req_hostname = "UNKNOWN_HOST";
		}else{
		    req_hostname = ntoa( &usa );
		}
	}
    /* Pound it to lower case. */
    for ( cp = req_hostname; *cp != '\0'; ++cp ){
    	if ( isupper( *cp ) )
	    *cp = tolower( *cp );
    }
    (void) snprintf( vfile, sizeof(vfile), "%s/%s", req_hostname, file );
	printf("vfile=%s\n", vfile);
    return vfile;
}

static void do_file( void )
{
	char buf[10000];
	char mime_encodings[500];
	const char* mime_type;
	char fixed_mime_type[500];
	char* cp;
	int fd;

	if(pathinfo != (char*)0){
		send_error(404, "Not Found", "", "File not found.");
	}
	fd = open(file, O_RDONLY);
	if(fd < 0){
		syslog(LOG_INFO, "%.80s File \"%.80s\" is protected",
	    	ntoa( &client_addr ), path );
		send_error( 403, "Forbidden", "", "File is protected." );
	}
	mime_type = figure_mime(file, mime_encodings, sizeof(mime_encodings));
	printf("mime_encodings =%s\n", mime_encodings);
	snprintf(fixed_mime_type, sizeof(fixed_mime_type), mime_type, charset);
	//如果文件没有改动
	if(if_modified_since != (time_t)-1 &&
		if_modified_since >= sb.st_mtime){
		add_headers(304, "Not Modified", "", mime_encodings, fixed_mime_type,
			(off_t)-1, sb.st_mtime);
		send_response();
		return;
	}
	printf("fixed_mime_type=%s\n", fixed_mime_type);
	add_headers(200, "OK", "", mime_encodings, fixed_mime_type,
		sb.st_size, sb.st_mtime);
	send_response();
	if(method == METHOD_HEAD){
		return;
	}
	if(sb.st_size > 0){
#ifdef HAVE_SENDFILE
		my_sendfile(fd, conn_fd, 0, sb.st_size);
#else /*HAVE_SENDFILE*/
		send_via_write(fd, sb.st_size);
#endif /*HAVE_SENDFILE*/
	}

	close(fd);
}

#ifdef HAVE_SENDFILE
static int my_sendfile( int fd, int socket, off_t offset, size_t nbytes )
{
#ifdef HAVE_LINUX_SENDFILE
	off_t lo = offset;
	return sendfile( socket, fd, &lo, nbytes );
#else /* HAVE_LINUX_SENDFILE */
	return sendfile( fd, socket, offset, nbytes, (struct sf_hdtr*) 0, (off_t*) 0, 0 );
#endif /* HAVE_LINUX_SENDFILE */
}
#endif /* HAVE_SENDFILE */

static void send_via_write( int fd, off_t size )
{
	if(size <= SIZE_T_MAX){
		size_t length = (size_t)size;
		void* ptr = mmap(0, length, PROT_READ, MAP_PRIVATE, fd, 0);
		if(ptr != MAP_FAILED){
			my_write(ptr, length);
			munmap(ptr, length);
		}
	}else{ //mmap can't deal with files larger than 2GB
		char buf[30000];
		ssize_t r, r2;

		for(;;){
			r = read(fd, buf, sizeof(buf));
			if(r < 0 && (errno == EINTR || errno == EAGAIN)){
				sleep(1);
				continue;
			}
			if(r <= 0){
				return;
			}
			for(;;){
				r2 = my_write(buf, r);
				if(r2 < 0 && (errno == EINTR || errno == EAGAIN)){
					sleep(1);
					continue;
				}
				if(r2 != r){
					return;
				}
				break;
			}
		}
	}
}

static void do_dir( void )
{
	char buf[10000];
	size_t buflen;
	char* contents;
	size_t contents_size, contents_len;

	int n, i;
	struct dirent** dl;
	char* name_info;

	if(pathinfo != (char*)0){
		send_error(404, "Not Found", "", "File not found.");
	}

	n = scandir(file, &dl, NULL, alphasort);
	if(n < 0){
		syslog(LOG_INFO, "%.80s Directory \"%.80s\" is protected",
	    	ntoa( &client_addr ), path );
		send_error( 403, "Forbidden", "", "Directory is protected." );
	}

	contents_size = 0;
	buflen = snprintf( buf, sizeof(buf), "\
	<HTML>\n\
	<HEAD><TITLE>Index of %s</TITLE></HEAD>\n\
	<BODY BGCOLOR=\"#99cc99\" TEXT=\"#000000\" LINK=\"#2020ff\" VLINK=\"#4040cc\">\n\
	<H4>Index of %s</H4>\n\
	<PRE>\n",
	file, file );
	add_to_buf(&contents, &contents_size, &contents_len, buf, buflen);

	for(i = 0; i < n; ++i){
		name_info = file_details(file, dl[i]->d_name);
		add_to_buf(&contents, &contents_size, &contents_len, name_info, strlen(name_info));
	}

	buflen = snprintf( buf, sizeof(buf), "\
	</PRE>\n\
	<HR>\n\
	<ADDRESS><A HREF=\"%s\">%s</A></ADDRESS>\n\
	</BODY>\n\
	</HTML>\n",
	SERVER_URL, SERVER_SOFTWARE );
	add_to_buf(&contents, &contents_size, &contents_len, buf, buflen);
	add_headers(200, "OK", "", "", "text/html; charset=%s", contents_len, sb.st_mtime);
	if(method != METHOD_HEAD){
		add_to_response(contents, contents_len);
	}
	send_response();
}

#ifdef HAVE_SCANDIR
static char* file_details( const char* dir, const char* name )
{
	struct stat sb;
	char f_time[20];
	static char encname[1000];
	static char buf[2000];

	snprintf(buf, sizeof(buf), "%s/%s", dir, name);
	if(lstat(buf, &sb) < 0){
		return "???";
	}
	strftime(f_time, sizeof(f_time), "%d%b%Y %H:%M", localtime(&sb.st_mtime));
	strencode(encname, sizeof(encname), name);
	(void) snprintf(buf, sizeof( buf ), 
		"<A HREF=\"%s\">%-32.32s</A>    %15s %14lld\n",
		encname, name, f_time, (int64_t) sb.st_size );
    return buf;
}

static void strencode( char* to, size_t tosize, const char* from )
{
	int tolen;
	for(tolen = 0; *from != '\0' && tolen+4 < tosize; ++from){
		//字母或数字 || "/_.-~"中的一个字符
		if(isalnum(*from) || strchr("/_.-~", *from) != (char*)0){
			*to = *from;
			++to;
			++tolen;
		}else{
			sprintf(to, "%%%02x", (int)* from & 0xff);
			to += 3;
			tolen += 3;
		}
	}
	*to = '\0';
}
#endif /* HAVE_SCANDIR */

static void auth_check( char* dirname )
{

}

static void handle_request(void)
{
	printf("handle_request start...\n");
	char* method_str;
	char* line;
	char* cp;
	int r, file_len, i;
	const char* index_names[] = {
	"index.html", "index.htm", "index.xhtml", "index.xht", "Default.htm",
	"index.cgi" };

	signal(SIGALRM, handle_read_timeout);
	alarm(READ_TIMEOUT); //send SIGALRM signal in READ_TIMEOUT seconds

	remoteuser = (char*)0;
	method = METHOD_UNKNOWN;
	path = (char*)0;
	pathinfo = (char*)0;
	file = (char*)0;
	query = "";
	protocol = (char*)0;
	status = 0;
	bytes = -1;
	req_hostname = (char*)0;

	authorization = (char*) 0;
    content_type = (char*) 0;
    content_length = -1;
    cookie = (char*) 0;
    host = (char*) 0;
    if_modified_since = (time_t) -1;
    referer = "";
    useragent = "";

    //Read in the request
    start_request();
    for(;;){
    	char buf[10000];
    	int r = my_read(buf, sizeof(buf)); //读取浏览器发送的请求
    	if(r < 0 && (errno == EINTR || errno == EAGAIN)){
    		continue;
    	}
    	if(r <= 0){
    		break;
    	}
    	alarm(READ_TIMEOUT); //60 seconds
    	add_to_request(buf, r);
    	if ( strstr( request, "\015\012\015\012" ) != (char*) 0 ||
	     strstr( request, "\012\012" ) != (char*) 0 )
	    break;
    }

	printf("request =%s\n", request);
    //1.请求方法
    method_str = get_request_line();
    printf("method_str=%s\n", method_str);
    if(method_str == (char*)0){
    	send_error( 400, "Bad Request", "", "Can't parse request." );
    }
    //2.请求路径,截取字符串:从" \t\012\015"出现的位置到末尾
    path = strpbrk(method_str, " \t\012\015");
    printf("path =%s\n", path); //path = / HTTP/1.1
    if(path == (char*)0){
    	send_error(400, "Bad Request", "", "Can't parse request.");
    }
    *path++ = '\0'; //添加结束符
    size_t n = 0;
    //检索字符串 str1 中第一个不在字符串 str2 中出现的字符下标。
    //strspn("ABCDE123","ABC"),返回3
    n = strspn(path, " \t\012\015");
    path += n;

    //3.请求协议
    protocol = strpbrk(path, " \t\012\015");
    if(protocol == (char*)0){
    	send_error(400, "Bad Request", "", "Can't parse request.");
    }
    *protocol++ = '\0';
    printf("protocol=%s\n", protocol);
    protocol += strspn( protocol, " \t\012\015" );
    //4.查询条件
    query = strchr(path, '?');
    printf("query=%s\n", query);
    if(query == (char*)0){
    	query = "";
    }else{
    	*query++ = '\0';
    }

    //Parse the rest the request headers
 	//Host: 192.168.179.128:8001
	// Connection: keep-alive
	// Cache-Control: max-age=0
	// Upgrade-Insecure-Requests: 1
	// User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36
	// Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
	// Accept-Encoding: gzip, deflate
	// Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7
	// If-Modified-Since: Wed, 29 Jun 2005 17:32:02 GMT
    while((line = get_request_line()) != (char*) 0){
    	printf("line =%s\n", line);
    	if(line[0] == '\0'){
    		break;
    	}else if(strncasecmp(line, "Authorization:", 14) == 0){
    		cp = &line[14];
    		cp += strspn(cp, " \t");
    		authorization = cp;
    	}else if(strncasecmp(line, "Content-Length:", 15) == 0){
    		cp = &line[15];
    		cp += strspn(cp, " \t");
    		content_length = atol(cp);
    	}else if(strncasecmp(line, "Content-Type:", 13) == 0){
    		cp = &line[13];
    		cp += strspn(cp, " \t");
    		content_type = cp;
    	}else if(strncasecmp(line, "Cookie:", 7) == 0){
    		cp = &line[7];
    		cp += strspn(cp, " \t");
    		cookie = cp;
    	}else if(strncasecmp(line, "Host:", 5) == 0){
    		cp = &line[5];
    		cp += strspn(cp, " \t");
    		host = cp;
    		if(strchr(host, '/') != (char*)0 || host[0] =='.'){
    			send_error(400, "Bad Request", "", "Can't parse request.");
    		}
    	}else if(strncasecmp(line, "If-Modified-Since:", 18) == 0){
    		cp = &line[18];
    		cp += strspn(cp, " \t");
    		//Parse character array to date
    		if_modified_since = tdate_parse(cp);
    	}else if(strncasecmp(line, "Referer:", 8) == 0){
    		cp = &line[8];
    		cp += strspn(cp, " \t");
    		referer = cp;
    	}else if(strncasecmp(line, "User-Agent:", 11) == 0){
    		cp = &line[11];
    		cp += strspn(cp, " \t");
    		useragent = cp;
    	}
    } /*end while((line = get_request_line()) != (char*) 0)*/

    if(strcasecmp(method_str, get_method_str(METHOD_GET)) == 0){
    	method = METHOD_GET;
    }else if(strcasecmp(method_str, get_method_str(METHOD_HEAD)) == 0){
    	method = METHOD_HEAD;
    }else if(strcasecmp(method_str, get_method_str(METHOD_POST)) == 0){
    	method = METHOD_POST;
    }else {
    	send_error( 501, "Not Implemented", "", "That method is not implemented." );
    }
    printf("before docode path=%s\n", path);
    strdecode(path, path);
    
    if(path[0] != '/'){
    	send_error(400, "Bad Request", "", "Bad filename.");
    }
    file = &(path[1]);
    printf("before de_dotdot file=%s\n", file);
    de_dotdot(file);
    printf("after de_dotdot file=%s\n", file);
    if(file[0] == '\0'){
    	file = "./";
    }
    /*以下格式文件不合法:
    1. "/"开头
    2. 只有".."
    3. "../"开头
    */
    if(file[0] == '/' || 
    	(file[0] == '.' && file[1] == '.') &&
    	(file[2] == '\0' || file[2] == '/')){
    	printf("Illegal filename: %s\n", file);
    	send_error(400, "Bad Request", "", "Illegal filename");
    }
    if(vhost){
    	file = virtual_file(file);
    }
    signal(SIGALRM, handle_write_timeout);
    alarm(WRITE_TIMEOUT);
    printf("stat file=%s\n", file);
    r = stat(file, &sb);
    if(r < 0){
    	r = get_pathinfo();
    }
    if(r < 0){
    	send_error(404, "Not Found", "", "File not found");
    }
    file_len = strlen(file);
    //Not a directory
    if(!S_ISDIR(sb.st_mode)){
    	printf("Not a directory!\n");
    	while(file[file_len - 1] == '/'){
    		file[file_len - 1] = '\0';
    		--file_len;
    	}
    	do_file();
    }else{
    	printf("Is a directory!\n");
    	char idx[10000];
    	if(file[file_len - 1] != '/' && pathinfo == (char*)0){
    		char location[10000];
    		if(query[0] != '\0'){
    			snprintf(location, sizeof(location), "Location: %s/?%s", path, query);
    		}else{
    			snprintf(location, sizeof(location), "Location: %s/", path);
    		}
    		send_error(302, "Found", location, "Directories must end with a slash.");
    	}

    	/*check for an index file.*/
    	for ( i = 0; i < sizeof(index_names) / sizeof(char*); ++i )
	    {
		    (void) snprintf( idx, sizeof(idx), "%s%s", file, index_names[i] );
			printf("idx=%s\n", idx);
		    if ( stat( idx, &sb ) >= 0 ){
				file = idx;
				do_file();
				goto got_one;
			}
	    }

	    /* Nope, no index file, so it's an actual directory request. */
		do_dir();

		got_one: ;
    }
}

static void start_request( void )
{
	request_size = 0;
	request_idx = 0;
}

static ssize_t my_read( char* buf, size_t size )
{
	return read( conn_fd, buf, size );
}

static ssize_t my_write( char* buf, size_t size )
{
	return write(conn_fd, buf, size);
}

static void add_to_request( char* str, size_t len )
{
	add_to_buf( &request, &request_size, &request_len, str, len );
}

static void add_to_response( char* str, size_t len )
{
	add_to_buf( &response, &response_size, &response_len, str, len );
}

static void
add_to_buf( char** bufP, size_t* bufsizeP, size_t* buflenP, char* str, size_t len )
{
	if(*bufsizeP == 0){
		//一次性分配读取到的字节数+500 bytes的内存
		*bufsizeP = len + 500;
		*buflenP = 0;
		*bufP = (char*)e_malloc(*bufsizeP);
	}else if(*buflenP + len >= *bufsizeP){
		*bufsizeP = *buflenP + len + 500;
		*bufP = (char*)e_realloc((void*)*bufP, *bufsizeP);
	}
	(void) memmove( &((*bufP)[*buflenP]), str, len );
	*buflenP += len;
	(*bufP)[*buflenP] = '\0';
}

/**
将"\r\n"前的字符串返回(不包含"\r\n");同时将"\r\n"变成"\0\0"
**/
static char* get_request_line( void )
{
    int i;
    char c;
    printf("request_idx=%d, request_len=%d",request_idx, request_len);
    for ( i = request_idx; request_idx < request_len; ++request_idx )
	{
		c = request[request_idx];
		if ( c == '\012' || c == '\015' ) //'\n' or '\r'
	    {
	    	request[request_idx] = '\0';
	    	++request_idx;
	    	if ( c == '\015' && request_idx < request_len &&
		 		request[request_idx] == '\012' )
			{
				request[request_idx] = '\0';
				++request_idx;
			}
	    	return &(request[i]);
	    }
	}
    return (char*) 0;
}

static void send_error( int s, char* title, char* extra_header, char* text )
{
	add_headers(
	s, title, extra_header, "", "text/html; charset=%s", (off_t) -1, (time_t) -1 );

	send_error_body( s, title, text );

	send_error_tail();

	send_response();

	exit( 1 );
}

static void add_headers( int s, char* title, char* extra_header, char* me, char* mt, off_t b, time_t mod )
{
	time_t now, expires;
	char timebuf[100];
	char buf[10000];
	int buflen;
	int s100;
	const char* rfc1123_fmt = "%a, %d %b %Y %H:%M:%S GMT";
	status = s;
	bytes = b;
	start_response();
	buflen = snprintf(buf, sizeof(buf), "%s %d %s\015\012", protocol, status, title);
	add_to_response(buf, buflen);
	buflen = snprintf(buf, sizeof(buf), "Server: %s\015\012", SERVER_SOFTWARE);
	add_to_response(buf, buflen);
	now = time((time_t*)0);
	strftime(timebuf, sizeof(timebuf), rfc1123_fmt, gmtime(&now));
	buflen = snprintf(buf, sizeof(buf), "Date: %s\015\012", timebuf);
	add_to_response(buf, buflen);
	s100 = status / 100;
	if(s100 != 2 && s100 != 3){
		buflen = snprintf( buf, sizeof(buf), "Cache-Control: no-cache,no-store\015\012" );
		add_to_response( buf, buflen );
	}
	if(extra_header != (char*)0 && extra_header[0] != '\0'){
		buflen = snprintf( buf, sizeof(buf), "%s\015\012", extra_header );
		add_to_response( buf, buflen );
	}
	if(me != (char*)0 && me[0] != '\0'){
		buflen = snprintf(buf, sizeof(buf), "Content-Encoding: %s\015\012", me);
		add_to_response(buf, buflen);
	}

	if(mt != (char*)0 && mt[0] != '\0'){
		buflen = snprintf(buf, sizeof(buf), "Content-Type: %s\015\012", mt);
		add_to_response(buf, buflen);
	}

	if(bytes > 0){
		buflen = snprintf(buf, sizeof(buf), "Content-Length: %lld\015\012", (int64_t)bytes);
		add_to_response(buf, buflen);
	}

	if(max_age >= 0){
		expires = now + max_age;
		strftime(timebuf, sizeof(timebuf), rfc1123_fmt, gmtime(&expires));
		buflen = snprintf(buf, sizeof(buf),
			"Cathe-Control: max-age=%d\015\012Expires: %s\015\012", max_age, timebuf);
		add_to_response(buf, buflen);
	}

	if(mod != (time_t)-1){
		strftime(timebuf, sizeof(timebuf), rfc1123_fmt, gmtime(&mod));
		buflen = snprintf(buf, sizeof(buf), "Last-Modified: %s\015\012", timebuf);
		add_to_response(buf, buflen);
	}
	buflen = snprintf(buf, sizeof(buf), "Connection: close\015\012\015\012");
	add_to_response(buf, buflen);
}

static void send_error_body( int s, char* title, char* text )
{
	char filename[1000];
    char buf[10000];
    int buflen;

    if ( vhost && req_hostname != (char*) 0 )
	{
		/* Try virtual-host custom error page. */
		(void) snprintf(filename, sizeof(filename), "%s/%s/err%d.html",
		    req_hostname, ERR_DIR, s );
		if ( send_error_file( filename ) )
		    return;
	}

    /* Try server-wide custom error page. */
    (void) snprintf(filename, sizeof(filename), "%s/err%d.html", ERR_DIR, s );
    if ( send_error_file( filename ) )
		return;

    /* Send built-in error page. */
    buflen = snprintf(
	buf, sizeof(buf), "\
	<HTML>\n\
	<HEAD><TITLE>%d %s</TITLE></HEAD>\n\
	<BODY BGCOLOR=\"#cc9999\" TEXT=\"#000000\" LINK=\"#2020ff\" VLINK=\"#4040cc\">\n\
	<H4>%d %s</H4>\n",
	s, title, s, title );
    add_to_response( buf, buflen );
    buflen = snprintf( buf, sizeof(buf), "%s\n", text );
    add_to_response( buf, buflen );
}

static int send_error_file( char* filename )
{
	FILE* fp;
	char buf[1000];
	size_t r;

	fp = open(filename, "r");
	if(fp == (FILE*)0){
		return 0;
	}
	for(;;){
		r = fread(buf, 1, sizeof(buf), fp);
		if(r == 0){
			break;
		}
		add_to_response(buf, r);
	}
	fclose(fp);
	return 1;
}

static void send_error_tail( void )
{
	char buf[500];
	int buflen;
	if(match("**MSIE**", useragent)){
		int n;
		buflen = snprintf(buf, sizeof(buf), "<!--\n");
		add_to_response(buf, buflen);
		for(n = 0; n < 6; ++n){
			 buflen = snprintf( buf, sizeof(buf), "Padding so that MSIE deigns to show this error instead of its own canned one.\n" );
			 add_to_response(buf, buflen);
		}
		buflen = snprintf(buf, sizeof(buf), "-->\n");
		add_to_response(buf, buflen);
	}
	buflen = snprintf( buf, sizeof(buf), "\
	<HR>\n\
	<ADDRESS><A HREF=\"%s\">%s</A></ADDRESS>\n\
	</BODY>\n\
	</HTML>\n",
	SERVER_URL, SERVER_SOFTWARE );
	printf("SERVER_URL=%s, SERVER_SOFTWARE=%s\n", SERVER_URL, SERVER_SOFTWARE);
    add_to_response( buf, buflen );
}

static void send_response( void )
{
	my_write(response, response_len);
}

static char* get_method_str( int m ){
	switch ( m ){
		case METHOD_GET: return "GET";
		case METHOD_HEAD: return "HEAD";
		case METHOD_POST: return "POST";
		default: return "UNKNOWN";
	}
}

static void strdecode( char* to, char* from )
{
	for(; *from != '\0'; ++to, ++from){
		if(from[0] == '%' && isxdigit(from[1]) && isxdigit(from[2])){
			//十六进制 转 十进制
			*to = hexit(from[1]) * 16 + hexit(from[2]);
			from += 2;
		}else{
			*to = *from;
		}	
	}
	*to = '\0';
}

static void handle_read_timeout(int sig)
{
	syslog( LOG_INFO, "%.80s connection timed out reading", ntoa( &client_addr ) );
    send_error(408, "Request Timeout", "",
		"No request appeared within a reasonable time period." );
}

static void usage()
{
	printf("-p port, -h host\n");
}

static void lookup_hostname(usockaddr* usa4P, size_t sa4_len, int* gotv4P)
{
	struct hostent* he;
	memset(usa4P, 0, sa4_len);
	//1.协议族
	usa4P->sa.sa_family = AF_INET;
	printf("hostname=%s\n", hostname); //null
	if(hostname == (char*)0){
		usa4P->sa_in.sin_addr.s_addr = htonl(INADDR_ANY);
	}else{
		//将点分十进制的ip转成整型,如"192.168.1.32" -> 12345
		usa4P->sa_in.sin_addr.s_addr = inet_addr(hostname);
		if(usa4P->sa_in.sin_addr.s_addr == -1){
			he = gethostbyname(hostname); //过时API,可用getaddrinfo()代替
			if(he == (struct hostent*)0){
				perror("gethostbyname");
				exit(1);
			}
			if(he->h_addrtype != AF_INET){
				fprintf(stderr, "%s: %.80s - non-IP network address\n", argv0,
		    		hostname );
				exit(1);
			}
			//2.IP
			//#define h_addr h_addr_list[0] /* for backward compatibility */
			memmove(&usa4P->sa_in.sin_addr.s_addr, he->h_addr, he->h_length);
		}
	}
	//端口
	usa4P->sa_in.sin_port = htons(port);
}

int main(int argc, char** argv)
{
	int argn;
	struct passwd* pwd;
	uid_t uid = 32767;
	gid_t gid = 32767;
	usockaddr host_addr4;
	int gotv4;
	fd_set lfdset;
	int maxfd;
	usockaddr usa;
	int sz, r;
	char* cp;

	argv0 = argv[0];
	debug = 0;
	port = 0;
	user = DEFAULT_USER;
	hostname = (char*)0;
	charset = DEFAULT_CHARSET;
	vhost = 0;
	argn = 1;
	while(argn < argc && argv[argn][0] == '-')
	{
		if(strcmp(argv[argn], "-p") == 0 && argn + 1 < argc){
			++argn;
			port = (unsigned short)atoi(argv[argn]);
		}else if(strcmp(argv[argn], "-h") == 0 && argn + 1 < argc){
			++argn;
			hostname = argv[argn];
		}else{
			usage();
		}
		++argn;
	} /*end while(argn < argc && argv[argn][0] == '-')*/

	if(argn != argc){
		usage();
	}
	if(port == 0){
		port = DEFAULT_HTTP_PORT;
	}
	//If we're root and we're going to become another user
	if(getuid() == 0){
		//获取user="nobody"的用户信息,如:用户名,密码,组id,用户id,家目录
		pwd = getpwnam(user); 
		if(pwd == (struct passwd*)0){
			fprintf(stderr, "%s, unknown user:%s\n",argv0, user);
			exit(1);
		}
		uid = pwd->pw_uid;
		gid = pwd->pw_gid;
	}
	//给host_addr4赋值 协议族,IP, 端口
	lookup_hostname(&host_addr4, sizeof(host_addr4), &gotv4);
	if(hostname == (char*)0){
		//获取[进程UTS(UNIX Time Sharing)空间]的hostname
		gethostname(hostname_buf, sizeof(hostname_buf));
		hostname = hostname_buf;
		printf("hostname = %s\n", hostname); //localhost.localdomain
	}
	if(!gotv4){
		fprintf(stderr, "%s cannot find any valid address.\n", argv0);
		listen4_fd = -1;
		exit(1);
	}else{
		//给套接字listen4_fd绑定IP,端口;并监听
		listen4_fd = initialize_listen_socket(&host_addr4);
	}
	if(! debug){
#ifdef HAVE_DAEMON
	printf("HAVE_DAEMON==\n");
	if(daemon(1, 1) < 0){ //不改变当前工作目录, 不将标准输入,输出,错误重定向到/dev/null
		perror("daemon");
		exit(1);
	}
#else
	printf("switch(fork())\n");
	switch(fork()){
		case 0: 
			break;
		case -1: 
			perror("fork");
			exit(1);
		default:
			exit(0);
	}
#ifdef HAVE_SETSID
	setsid(); //使当前进程成为会话(session)的领导,且成为进程组(process group)的领导
#endif /*HAVE_SETSID*/
#endif /*HAVE_DAEMON*/
	} /*if(! debug)*/
	else
	{
#ifdef HAVE_SETSID
		setsid();
#endif /*HAVE_SETSID*/
	}

	//initializes the tzname variable from the TZ environment variable.
	tzset();
	if(getuid == 0){ //If we're root
		printf("we are root!\n");
		////drop all of this process's supplementary groups
		if(setgroups(0, (gid_t*)0) < 0){
			perror("setgroups");
			exit(1);
		}
		// sets the effective group ID of the calling process.
		if(setgid(gid) < 0){
			perror("setgid");
			exit(1);
		}
		//initialize the supplementary group access list
		if(initgroups(user, gid) < 0){
			perror("initgroups");
		}
	}

	//get current directory
	getcwd(cwd, sizeof(cwd) - 1);
	if(cwd[strlen(cwd) - 1] != '/'){
		strcat(cwd, "/");
	}
	if(getuid() == 0){
		printf("again we are root!\n");
		if(setuid(uid) < 0){
			perror("setuid");
			exit(1);
		}
	}

	//catch various signals
	signal(SIGTERM, handle_sigterm);
	signal(SIGINT, handle_sigterm);
	signal(SIGUSR1, handle_sigterm);
	signal(SIGHUP, handle_sighup);
	signal(SIGCHLD, handle_sigchld);
	signal(SIGPIPE, SIG_IGN);

	init_mime();
	if(hostname == (char*)0){
		syslog(LOG_NOTICE, "%.80s starting on port %d\n", SERVER_SOFTWARE, port);
	}else{
		syslog(
	    LOG_NOTICE, "%.80s starting on %.80s, port %d", SERVER_SOFTWARE,
	    hostname, (int) port );
	}

	//Main loop
	for(;;){
		FD_ZERO(&lfdset);
		maxfd = -1;
		if(listen4_fd != -1){
			FD_SET(listen4_fd, &lfdset); //将listen4_fd加入文件描述符集合lfdset中
			if(listen4_fd > maxfd)
				maxfd = listen4_fd;
		}
		//监听描述符集合中的文件描述符,直到有可用的(可读或可写)文件描述符出现
		if(select(maxfd + 1, &lfdset, NULL, NULL, NULL) < 0){
			if(errno == EINTR || errno == EAGAIN){
				continue; //如果遇到信号打断或系统分配内核资源失败,则重试
			}
			perror("select");
			exit(1);
		}

		//Accept the new connection
		sz = sizeof(usa);
		if(listen4_fd != -1 && FD_ISSET(listen4_fd, &lfdset)){
			conn_fd = accept(listen4_fd, &usa.sa, &sz);
			printf("conn_fd=%d\n", conn_fd);
		}else{
			fprintf(stderr, "%s: select failed\n", argv0);
			exit(1);
		}
		if(conn_fd < 0){
			if(errno == EINTR || errno == EAGAIN){
				continue; //try again
			}
#ifdef EPROTO
	    	if ( errno == EPROTO )
			continue;	/* try again */
#endif /* EPROTO */
			perror("accept");
			exit(1);
		}

		//Fork a sub-process to handle the connection
		r = fork();
		if(r < 0){
			perror("fork");
			exit(1);
		}
		if(r == 0){ //child process
			client_addr = usa;
			if(listen4_fd != -1)
				close(listen4_fd);
			handle_request();
			exit(0);
		}
		close(conn_fd);
	} /*end for(;;)*/
}