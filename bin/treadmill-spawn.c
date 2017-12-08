#include "treadmill-spawn-common.h"
#include <getopt.h>
#include <jansson.h>
#include <pwd.h>
#include <stdbool.h>
#include <sys/poll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_TIMEOUT           60 * 1000 // 60 seconds
#define DEFAULT_RECONNECT_TIMEOUT 5 * 60 // 5 mins
#define FILE_READ_LENGTH          1024
#define NFDS                      2
#define SIGNAL_FDI                0
#define SOCKET_FDI                1
#define UDS_BUFFER_LENGTH         4096
#define MAX_HOSTNAME              255
#define MAX_EVENT                 255
#define MAX_SERVICE_NAME          255
#define MAX_UNIQUE_ID             13
#define MAX_WHY                   255

typedef enum {TEXT, JSON, RAW, NONE} format_mode;

typedef struct {
    bool        debug;
    bool        is_file;
    bool        reconnect;
    bool        stop;
    bool        unlink;
    char        *dir;
    char        *id;
    char        *manifest;
    char        *name;
    char        instance[MAX_INSTANCE_NAME];
    double      reconnect_timeout;
    int         timeout;
    bool        service_exit;
    format_mode mode;
} launch_settings;

typedef struct {
    size_t start;
    size_t end;
    char storage[UDS_BUFFER_LENGTH];
} ring_buffer;

typedef struct {
    bool finished;
    int code;
    int sig;
} uds_rc;

typedef struct {
    struct tm event_time;
    char      server[MAX_HOSTNAME + 1];
    char      event_name[MAX_EVENT + 1];
    char      service_name[MAX_SERVICE_NAME + 1];
    char      unique_id[MAX_UNIQUE_ID + 1];
    char      where[MAX_HOSTNAME + 1];
    char      why[MAX_WHY + 1];
    bool      out_of_memory;
    int       return_code;
    int       signal;
} event;

typedef void (*output)(launch_settings*, char*);

static inline
int init_signalfd(launch_settings *settings)
{
    sigset_t set;
    int fd;

    if (sigemptyset(&set) < 0)
        ERR_EXIT(settings->id, "sigfillset()");

    if (sigaddset(&set, SIGTERM) < 0)
        ERR_EXIT(settings->id, "sigaddset(SIGTERM)");

    if (sigaddset(&set, SIGINT) < 0)
        ERR_EXIT(settings->id, "sigaddset(SIGINT)");

    if (sigprocmask(SIG_BLOCK, &set, NULL) < 0)
        ERR_EXIT(settings->id, "sigprocmask(SIG_BLOCK)");

    fd = signalfd(-1, &set, 0);
    if (fd < 0)
        ERR_EXIT(settings->id, "signalfd()");

    return fd;
}

static
int open_uds(launch_settings *settings)
{
    struct sockaddr_un addr;
    int sockfd;

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;

    // starts at 1 because 0 indicates using the abstract namespace
    strncpy(&addr.sun_path[1], "/tms/", 5);
    strncpy(&addr.sun_path[6], settings->id, sizeof(addr.sun_path) - 7);

    if (settings->debug)
        log_debug(settings->id, "Opening UDS at '\\0%s'.", &addr.sun_path[1]);

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd == -1)
        ERR_EXIT(settings->id, "socket()");

    if (bind(sockfd, (const struct sockaddr *) &addr,
             sizeof(struct sockaddr_un)) == -1)
        ERR_EXIT(settings->id, "bind(\\0%s)", &addr.sun_path[1]);

    if (listen(sockfd, 1) == -1)
        ERR_EXIT(settings->id, "listen()");

    return sockfd;
}

static
void read_manifest_to_file(launch_settings *settings)
{
    size_t tmppath_size = strlen(settings->dir) + 5 + strlen(settings->id) + 6;
    size_t finalpath_size = strlen(settings->dir) + strlen(settings->id) + 6;
    char buffer[FILE_READ_LENGTH];
    char tmppath[tmppath_size];
    char finalpath[finalpath_size];
    FILE *out;
    int ret;

    // write to .tmp/instance.yml first then rename to instance.yml
    snprintf(tmppath, tmppath_size, "%s/.tmp/%s.yml", settings->dir,
             settings->id);

    if (settings->debug)
        log_debug(settings->id, "Writing manifest to '%s'.", tmppath);

    out = fopen(tmppath, "w");
    if (out == NULL)
        ERR_EXIT(settings->id, "fopen(%s)", tmppath);

    fprintf(out, "name: %s\n", settings->name);
    fprintf(out, "stop: %s\n", settings->stop ? "true" : "false");
    fprintf(out, "reconnect: %s\n", settings->reconnect ? "true" : "false");
    fprintf(out, "reconnect_timeout: %f\n", settings->reconnect_timeout);
    fprintf(out, "service_exit: %s\n",
            settings->service_exit ? "true" : "false");
    fprintf(out, "---\n");

    if (settings->manifest != NULL)
    {
        FILE *in = stdin;
        if (strcmp("-", settings->manifest) != 0)
        {
            settings->is_file = true;
            in = fopen(settings->manifest, "r");
        }

        if (in == NULL)
            ERR_EXIT(settings->id, "fopen(%s)", settings->manifest);

        while (ret = fread(buffer, sizeof(char), FILE_READ_LENGTH, in))
        {
            fwrite(buffer, sizeof(char), ret, out);
        }

        fclose(in);
    }

    fclose(out);

    snprintf(finalpath, finalpath_size, "%s/%s.yml", settings->dir,
             settings->id);

    if (settings->debug)
        log_debug(settings->id, "Renaming '%s' manifest to '%s'.", tmppath,
                  finalpath);

    if (rename(tmppath, finalpath) == -1)
    {
        int errno_tmp = errno;
        unlink(tmppath); // cleanup tmp file left over
        _err_exit(settings->id, __FILE__, __LINE__, errno_tmp,
                  "rename(%s, %s)", tmppath, finalpath);
    }
}

static
int accept_uds_connection(launch_settings *settings, const int sockfd)
{
    int datafd = accept(sockfd, 0, 0);
    if (datafd == -1)
        ERR_EXIT(settings->id, "accept");

    if (settings->debug)
        log_debug(settings->id, "Accepted UDS connection.");

    close(sockfd);

    return datafd;
}

static
bool process_line(launch_settings *settings, char *line, uds_rc *rc, output out)
{
    const static char init[] = INITIALIZE_PREFIX;
    const static char print[] = PRINT_PREFIX;
    const static char done[] = DONE_PREFIX;
    char *lineptr, *code, *pos;

    if (settings->debug)
        log_debug(settings->id, "Processing line '%s'.", line);

    if (strncmp(init, line, PREFIX_LENGTH) == 0)
    {
        strncpy(settings->instance, &line[PREFIX_LENGTH], MAX_INSTANCE_NAME);
        return false;
    }
    else if (strncmp(print, line, PREFIX_LENGTH) == 0)
    {
        if (out != NULL)
            (*out)(settings, &line[PREFIX_LENGTH]);

        return false;
    }
    else if (strncmp(done, line, PREFIX_LENGTH) == 0)
    {
        lineptr = &line[PREFIX_LENGTH];
        code = strsep(&lineptr, ".");
        if (code != NULL)
        {
            char *sig;

            rc->code = strtol(code, 0, 10);

            sig = strsep(&lineptr, ".");
            if (sig != NULL)
            {
                rc->sig = strtol(sig, 0, 10);
                rc->finished = true;
                return true;
            }
        }
    }

    log_error(settings->id, "Ignoring unknown message '%s'.", line);
    return false;
}

static
bool read_from_uds(launch_settings *settings, ring_buffer *buffer,
                   const int datafd, uds_rc *rc, output out)
{
    ssize_t count, result;
    struct iovec iov[2];

    if (buffer->start == buffer->end)
    {
        buffer->start = 0;
        buffer->end = UDS_BUFFER_LENGTH - 1;
    }

    if (buffer->start < buffer->end)
    {
        count = 1;
        iov[0].iov_base = &buffer->storage[buffer->start];
        iov[0].iov_len  = buffer->end - buffer->start;
    }
    else
    {
        count = 2;
        iov[0].iov_base = &buffer->storage[buffer->start];
        iov[0].iov_len  = UDS_BUFFER_LENGTH - buffer->start;
        iov[1].iov_base = &buffer->storage[0];
        iov[1].iov_len  = buffer->end;
    }

    result = readv(datafd, iov, count);

    if (result == -1)
    {
        ERR_EXIT(settings->id, "read()");
    }
    else if (result == 0)
    {
        log_error(settings->id, "UDS closed unexpectedly.");
        rc->code = SIGABRT;
        return true;
    }

    if (settings->debug)
        log_debug(settings->id, "Received %d bytes (%d, %d).", result,
                  buffer->start, buffer->end);

    buffer->end = (buffer->end + result - 1) % UDS_BUFFER_LENGTH;

    while(true)
    {
        char line[UDS_LINE_LENGTH + 1];
        bool should_continue = false;
        int i;

        memset(&line, 0, sizeof(line));

        for (i = 0; i < UDS_LINE_LENGTH; i++)
        {
            int pos;
            char c;

            if (result <= 0)
                return false;

            pos = (buffer->start + i) % UDS_BUFFER_LENGTH;
            c = buffer->storage[pos];
            result--;

            if (c == '\n')
            {
                if (process_line(settings, line, rc, out))
                    return true;

                buffer->start = (pos + 1) % UDS_BUFFER_LENGTH;
                should_continue = true;
                break;
            }
            else
            {
                line[i] = c;
            }
        }
        
        if (!should_continue)
        {
            // end of line reached but there is more data
            log_error(settings->id,
                      "Message too long '%s' - cannot continue.", line);
            rc->sig = SIGABRT;
            return true;
        }
    }

    return false;
}

static
void write_to_uds(launch_settings *settings, const int sockfd,
                  const char *message)
{
    if (settings->debug)
        log_debug(settings->id, "Writing '%s' to UDS.", message);

    if (write(sockfd, message, sizeof(message)) < 0)
        ERR_EXIT(settings->id, "write");
}

/*---- Formatting ------------------------------------------------------------*/

static
void convert_to_utc_tm(char *str, struct tm *result)
{
    struct tm local;
    time_t rawtime;

    memset(&local, 0, sizeof(local));

    strptime(str, "%s", &local);
    rawtime = mktime(&local);
    gmtime_r(&rawtime, result);
}

static
char *parse_service(char *payload, event *event)
{
    char *id, *name;
    if ((id = strsep(&payload, ".")) == NULL)
        return payload;

    strncpy(event->unique_id, id, MAX_UNIQUE_ID);

    if ((name = strsep(&payload, ".")) != NULL)
        strncpy(event->service_name, name, MAX_SERVICE_NAME);

    return payload;
}

static
char *parse_return(char *payload, event *event)
{
    char *pos = NULL;
    char *rc = NULL;
    char *sig = NULL;

    while ((pos = strsep(&payload, ".")) != NULL)
    {
        rc = sig;
        sig = pos;
    }

    if (rc != NULL)
        event->return_code = strtol(rc, 0, 10);

    if (sig != NULL)
        event->signal = strtol(sig, 0, 10);

    return payload;
}

static
void parse_payload(char *payload, event *event)
{
    if (strcmp(event->event_name, "scheduled") == 0)
        strncpy(event->where, payload, MAX_HOSTNAME);

    else if (strcmp(event->event_name, "configured") == 0)
        strncpy(event->unique_id, payload, MAX_UNIQUE_ID);

    else if (strcmp(event->event_name, "finished") == 0)
        parse_return(payload, event);

    else if (strcmp(event->event_name, "aborted") == 0)
        strncpy(event->why, payload, MAX_WHY);

    else if (strcmp(event->event_name, "killed") == 0)
    {
        if (strcmp(payload, "oom") == 0)
            event->out_of_memory = true;
    }

    else if (strcmp(event->event_name, "service_running") == 0)
        parse_service(payload, event);

    else if (strcmp(event->event_name, "service_exited") == 0)
        parse_return(parse_service(payload, event), event);
}

static
bool parse_line(char *line, event *event)
{
    char *token;
    int pos = 0;

    event->return_code = -1;
    event->signal = -1;

    while ((token = strsep(&line, ",")) != NULL)
    {
        ++pos;

        switch(pos)
        {
            case 1:
                convert_to_utc_tm(token, &event->event_time);
                break;
            case 2:
                strncpy(event->server, token, MAX_HOSTNAME);
                break;
            case 3:
                strncpy(event->event_name, token, MAX_EVENT);
                break;
            case 4:
                parse_payload(token, event);
                break;
        }
    }

    return pos == 4;
}

static
void output_text(launch_settings *settings, char *line)
{
    event event;
    char date[50];

    memset(&event, 0, sizeof(event));

    parse_line(line, &event);

    strftime(date, 50, "%a, %d %b %Y %H:%M:%S+0000", &event.event_time);

    if (strcmp(event.event_name, "scheduled") == 0)
        printf("[%s] %s - %s scheduled on %s\n", settings->id, date,
               settings->instance, event.server);

    else if (strcmp(event.event_name, "pending") == 0)
        printf("[%s] %s - %s pending\n", settings->id, date,
               settings->instance);

    else if (strcmp(event.event_name, "configured") == 0)
        printf("[%s] %s - %s/%s configured on %s\n", settings->id, date,
               settings->instance, event.unique_id, event.server);

    else if (strcmp(event.event_name, "deleted") == 0)
        printf("[%s] %s - %s deleted\n", settings->id, date,
               settings->instance);

    else if (strcmp(event.event_name, "finished") == 0)
        printf("[%s] %s - %s finished on %s\n", settings->id, date,
               settings->instance, event.server);

    else if (strcmp(event.event_name, "killed") == 0)
    {
        if (event.out_of_memory)
            printf("[%s] %s - %s killed, out of memory\n", settings->id, date,
                   settings->instance);
        else
            printf("[%s] %s - %s killed\n", settings->id, date,
                   settings->instance);
    }

    else if (strcmp(event.event_name, "aborted") == 0)
        printf("[%s] %s - %s aborted on %s [reason: %s]\n", settings->id, date,
               settings->instance, event.server, event.why);

    else if (strcmp(event.event_name, "service_running") == 0)
        printf("[%s] %s - %s/%s/service/%s running\n", settings->id, date,
               settings->instance, event.unique_id, event.service_name);

    else if (strcmp(event.event_name, "service_exited") == 0)
    {
        if (event.signal > 0)
            printf("[%s] %s - %s/%s/service/%s killed, signal: %s\n",
                   settings->id, date, settings->instance, event.unique_id,
                   event.service_name, strsignal(event.signal));
        else
            printf("[%s] %s - %s/%s/service/%s exited, return code: %d\n",
                   settings->id, date, settings->instance, event.unique_id,
                   event.service_name, event.return_code);
    }

    fflush(stdout);
}

static
void output_json(launch_settings *settings, char *line)
{
    event event;
    char* output;
    char date[26];

    memset(&event, 0, sizeof(event));

    parse_line(line, &event);

    strftime(date, 25, "%FT%TZ", &event.event_time);

    json_t *root = json_object();

    json_object_set_new(root, "id", json_string(settings->id));
    json_object_set_new(root, "instance", json_string(settings->instance));
    json_object_set_new(root, "time", json_string(date));
    json_object_set_new(root, "server", json_string(event.server));
    json_object_set_new(root, "event", json_string(event.event_name));

    if(event.service_name[0] != '\0')
        json_object_set_new(root, "service", json_string(event.service_name));

    if(event.unique_id[0] != '\0')
        json_object_set_new(root, "unique_id", json_string(event.unique_id));

    if(event.where[0] != '\0')
        json_object_set_new(root, "where", json_string(event.where));

    if(event.why[0] != '\0')
        json_object_set_new(root, "why", json_string(event.why));

    if(event.out_of_memory)
        json_object_set_new(root, "out_of_memory",
                            json_boolean(event.out_of_memory));

    if(event.return_code >= 0)
        json_object_set_new(root, "return_code",
                            json_integer(event.return_code));

    if(event.signal >= 0)
        json_object_set_new(root, "signal", json_integer(event.signal));

    output = json_dumps(root, 0);
    puts(output);
    fflush(stdout);

    json_decref(root);
    free(output);
}

static
void output_raw(launch_settings *settings, char *line)
{
    printf("%s,%s,%s\n", settings->id, settings->instance, line);
    fflush(stdout);
}


/*---- Command line ----------------------------------------------------------*/

static
void usage(int exit_status)
{
    FILE *out = NULL;

    if (exit_status == EXIT_SUCCESS)
        out = stdout;
    else
        out = stderr;

    fprintf(out,
       "usage: treadmill-spawn [OPTIONS] <ID> <MANIFIEST_DIR>\n"
       "\n"
       "  -h, --help            display this message and exit\n"
       "  -d, --debug           enables debug display\n"
       "  -o, --output          which output type (text/json/raw/none)\n"
       "  -m, --manifest        location of the manifest or - for STDIN\n"
       "  -u, --unlink          unlink manifest when application exits\n"
       "  -n, --name            the app name if different from <ID>\n"
       "  -s, --stop            stop's the treadmill app on launcher failure\n"
       "  -r, --reconnect       allow launcher to reconnect (with timeout "
                                "in secs)\n"
       "  -t, --timeout         the connection timeout in ms\n"
       "  -e, --service-exit    exit when the service exit event occurs\n"
    );

    exit(exit_status);
}

static
void parse_opts(int argc, char *argv[], launch_settings *settings)
{
    int index;

    static const struct option longopts[] = {
        { "help", no_argument, 0, 'h' },
        { "debug", no_argument, 0, 'd' },
        { "output", required_argument, 0, 'o' },
        { "manifest", required_argument, 0, 'm' },
        { "unlink", no_argument, 0, 'u' },
        { "name", required_argument, 0, 'n' },
        { "stop", no_argument, 0, 's' },
        { "reconnect", optional_argument, 0, 'r' },
        { "timeout", required_argument, 0, 't' },
        { "service-exit", no_argument, 0, 'e' },
        { NULL, 0, 0, 0 }
    };
    int c;

    while ((c = getopt_long(argc, argv, "+hdo:m:un:sr::t:e", longopts,
                            NULL)) != -1)
    {
        switch (c)
        {
            case 'h':
                usage(EXIT_SUCCESS);
                break;
            case 'd':
                settings->debug = true;
                break;
            case 'o':
                if (strcmp(optarg, "text") == 0)
                    settings->mode = TEXT;
                else if (strcmp(optarg, "json") == 0)
                    settings->mode = JSON;
                else if (strcmp(optarg, "raw") == 0)
                    settings->mode = RAW;
                else if (strcmp(optarg, "none") == 0)
                    settings->mode = NONE;
                else
                    usage(EXIT_FAILURE);
                break;
            case 'm':
                settings->manifest = optarg;
                break;
            case 'u':
                settings->unlink = true;
                break;
            case 'n':
                settings->name = optarg;
                break;
            case 's':
                settings->stop = true;
                break;
            case 'r':
                settings->reconnect = true;
                if (optarg != NULL)
                    settings->reconnect_timeout = atof(optarg);
                break;
            case 't':
                settings->timeout = atoi(optarg);
                break;
            case 'e':
                settings->service_exit = true;
                break;
            default:
                usage(EXIT_FAILURE);
        }
    }

    index = optind;
    if (index + 2 > argc)
        usage(EXIT_FAILURE);

    settings->id = argv[index++];
    if (settings->name == NULL)
        settings->name = settings->id;

    settings->dir = argv[index];
}

static
void check_settings(launch_settings *settings)
{
    if (strlen(settings->id) > MAX_ID)
    {
        log_error(settings->id, "Max ID size can be %d.", MAX_ID);
        exit(EXIT_FAILURE);
    }

    struct passwd *pws;
    pws = getpwuid(geteuid());

    if (pws == NULL)
    {
        log_error(settings->id, "Current user could not be determined.");
        exit(EXIT_FAILURE);
    }

    if ((strlen(pws->pw_name) + 1 + strlen(settings->name)) > MAX_APP_NAME)
    {
        log_error(settings->id, "Max name including id can be %d.",
                  MAX_APP_NAME);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[])
{
    launch_settings settings;
    ring_buffer buffer;
    uds_rc rc;
    output out = NULL;
    int sockfd, signalfd, timeout;
    struct pollfd fds[NFDS];
    bool connected = false;

    memset(&settings, 0, sizeof(settings));
    memset(&buffer, 0, sizeof(buffer));
    memset(&rc, 0, sizeof(rc));
    memset(&fds, 0, sizeof(fds));

    settings.timeout = DEFAULT_TIMEOUT;
    settings.reconnect_timeout = DEFAULT_RECONNECT_TIMEOUT;
    settings.mode = TEXT;

    parse_opts(argc, argv, &settings);
    check_settings(&settings);

    if (settings.mode == TEXT)
        out = &output_text;
    else if (settings.mode == JSON)
        out = &output_json;
    else if (settings.mode == RAW)
        out = &output_raw;

    signalfd = init_signalfd(&settings);
    sockfd = open_uds(&settings);

    read_manifest_to_file(&settings);

    fds[SIGNAL_FDI] = (struct pollfd) { signalfd, POLLIN, 0 };
    fds[SOCKET_FDI] = (struct pollfd) { sockfd, POLLIN, 0 };

    timeout = settings.timeout;
    while (true)
    {
        if (poll(fds, NFDS, timeout) == -1)
            ERR_EXIT(settings.id, "poll()");

        if (fds[SIGNAL_FDI].revents & POLLIN)
        {
            if (connected)
                write_to_uds(&settings, sockfd, "q");

            break;
        }

        if (fds[SOCKET_FDI].revents & POLLIN)
        {
            if (!connected)
            {
                sockfd = accept_uds_connection(&settings, sockfd);
                fds[SOCKET_FDI].fd = sockfd;
                connected = true;
                timeout = -1;
                continue;
            }
            else
            {
                if (read_from_uds(&settings, &buffer, sockfd, &rc, out))
                {
                    if (settings.debug)
                         log_debug(settings.id, "Complete (%d, %d).", rc.code,
                                   rc.sig);
                    break;
                }
            }
        }

        if (!connected)
        {
            log_error(settings.id, "UDS timeout.", settings.id);
            rc.sig = SIGABRT;
            break;
        }
    }

    close(sockfd);

    if (settings.unlink && settings.is_file && rc.finished)
        if (unlink(settings.manifest) == -1)
            log_error(settings.id, "Failed to unlink(%s).", settings.manifest);

    if (rc.sig > 0)
        raise(rc.sig);

    return rc.code;
}
