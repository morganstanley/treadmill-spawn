#include "treadmill-spawn-common.h"
#include <dirent.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <sys/inotify.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define EVENT_SIZE           ( sizeof (struct inotify_event) )
#define BUF_LEN              ( 1024 * ( EVENT_SIZE + 16 ) )
#define UDS_READ_LENGTH      1
#define NFDS                 3
#define STDIN_FDI            0
#define INOTIFY_FDI          2
#define WATCH_MASK           ( IN_CREATE | IN_MOVED_TO | IN_DELETE | \
                               IN_DELETE_SELF )

typedef struct {
    bool debug;
    char *zk2fs;
    int  num_shards;
    bool use_sow;
    char *sow;
    char *instance;
    bool service_exit;
} fstrace_settings;

typedef bool (*check_fn_t)(fstrace_settings*, const char*, const char*, char*);

static
void join_path(char *path, const char *path1, const char *path2)
{
    if ((path1[0] == '\0') || (path2[0] == '/'))
    {
        snprintf(path, PATH_MAX, "%s", path2);
        return;
    }

    if (path1[strlen(path1) - 1] == '/')
        snprintf(path, PATH_MAX, "%s%s", path1, path2);
    else
        snprintf(path, PATH_MAX, "%s/%s", path1, path2);
}

static
bool dedup_event(const char *event, char *last)
{
    char *strptr;
    int ts_len, ts_cmp;

    // Skip event with no ',', should never happen
    strptr = strchr(event, ',');
    if (!strptr)
        return true;

    // Skip event if it's older than the last one, events must differ on eq. ts
    ts_len = strptr - event;
    ts_cmp = strncmp(event, last, strptr - event);
    if (*last && (ts_cmp < 0 || (ts_cmp == 0 && strcmp(event, last) == 0)))
        return true;

    last[0] = '\0';
    strncat(last, event, NAME_MAX);

    return false;
}

static
void parse_service_exit(char *payload)
{
    char *pos = NULL;
    char *rc = NULL;
    char *sig = NULL;

    while ((pos = strsep(&payload, ".")) != NULL)
    {
        rc = sig;
        sig = pos;
    }

    printf("%s%s.%s\n", DONE_PREFIX, rc, sig);
}

static
bool process_event(fstrace_settings *settings, const char *event, char *last)
{
    bool done = false;
    int pos = 1;
    // NAME_MAX does not include null terminator
    char str[NAME_MAX + 1];
    char *strptr, *token;
    bool service_exit = false;

    if (dedup_event(event, last))
        return false;

    printf("%s%s\n", PRINT_PREFIX, event);
    fflush(stdout);

    str[0] = '\0';
    strncat(str, event, NAME_MAX);

    strptr = str;
    while (!done && (token = strsep(&strptr, ",")) != NULL)
    {
        if (pos < 3)
        {
            ++pos;
            continue;
        }

        if (pos == 4)
        {
            if (service_exit)
                parse_service_exit(token);
            else
                printf("%s%s\n", DONE_PREFIX, token);

            done = true;
            break;
        }

        if (settings->service_exit && strcmp(token, "service_exited") == 0)
        {
            service_exit = true;
            ++pos;
            continue;
        }

        if (strcmp(token, "finished") == 0)
        {
            ++pos;
            continue;
        }

        if (strcmp(token, "aborted") == 0)
        {
            printf("%s0.%d\n", DONE_PREFIX, SIGABRT);
            done = true;
        }
        else if (strcmp(token, "killed") == 0)
        {
            printf("%s0.%d\n", DONE_PREFIX, SIGABRT);
            done = true;
        }
        else if (strcmp(token, "deleted") == 0)
        {
            printf("%s0.%d\n", DONE_PREFIX, SIGABRT);
            done = true;
        }

        break;
    }

    if (done)
        fflush(stdout);

    return done;
}

static
bool check_trace_file(fstrace_settings *settings, const char *name,
                      const char *filter, char *last)
{
    int i;

    if (settings->debug)
        log_debug(settings->instance, "Checking trace file '%s' for '%s*'.",
                  name, filter);

    for (i = 0; filter[i] != '\0'; i++)
        if (name[i] != filter[i])
            return false;
    
    return process_event(settings, name + i, last);
}

static
bool check_trace_db(fstrace_settings *settings, const char *name,
              const char *filter, char *last)
{
    char sow_dir[PATH_MAX], db[PATH_MAX], path_pattern[PATH_MAX];
    bool done = false;
    sqlite3 *conn = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc;
    int filter_len;
    const char *event;

    if (name[0] == '.')
        return false;

    join_path(sow_dir, settings->zk2fs, settings->sow);
    join_path(db, sow_dir, name);

    snprintf(path_pattern, PATH_MAX, "%s*", filter);

    if (settings->debug)
        log_debug(settings->instance, "Checking trace database '%s' for '%s'.",
                  db, path_pattern);

    rc = sqlite3_open(db, &conn);
    if (rc)
    {
        log_error(settings->instance, sqlite3_errmsg(conn));
        sqlite3_close(conn);
        exit(EXIT_FAILURE);
    }

    rc = sqlite3_prepare_v2(conn,
        "SELECT path FROM trace WHERE path GLOB ? ORDER BY path",
        -1, &stmt, NULL
    );
    if (rc)
    {
        log_error(settings->instance, sqlite3_errmsg(conn));
        sqlite3_close(conn);
        exit(EXIT_FAILURE);
    }

    rc = sqlite3_bind_text(stmt, 1, path_pattern, -1, NULL);
    if (rc)
    {
        log_error(settings->instance, sqlite3_errmsg(conn));
        sqlite3_finalize(stmt);
        sqlite3_close(conn);
        exit(EXIT_FAILURE);
    }

    filter_len = strlen(filter);
    while (true)
    {
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW)
        {
            event = sqlite3_column_text(stmt, 0) + filter_len;
            if (process_event(settings, event, last))
            {
                done = true;
                break;
            }
        }
        else if (rc == SQLITE_DONE)
        {
            break;
        }
        else
        {
            log_error(settings->instance, "Unexpected sqlite3_step rc %d", rc);
            sqlite3_finalize(stmt);
            sqlite3_close(conn);
            exit(EXIT_FAILURE);
        }
    }

    sqlite3_finalize(stmt);
    sqlite3_close(conn);
    return done;
}

static
bool check_file(fstrace_settings *settings, const char *name,
                const char *filter, char *unused)
{
    if (settings->debug)
        log_debug(settings->instance, "Checking file '%s' for '%s'.",
                  name, filter);

    return strcmp(name, filter) == 0;
}

static
bool read_dir(fstrace_settings *settings, const char *dir, const char *filter,
              char *last, check_fn_t check_fn)
{
    bool done = false;
    struct dirent **namelist;
    int i, total;

    if (settings->debug)
        log_debug(settings->instance, "Scanning directory '%s'.", dir);

    total = scandir(dir, &namelist, NULL, alphasort);
    if (total < 0)
        ERR_EXIT(settings->instance, "scandir(%s)", dir);

    for (i = 0; i < total; i++)
    {
        if ((strcmp(namelist[i]->d_name, ".") != 0) &&
            (strcmp(namelist[i]->d_name, "..") != 0))
        {
            done = (*check_fn)(settings, namelist[i]->d_name, filter, last);
            if (done)
                break;
        }
    }

    free(namelist);
    return done;
}

static
void read_stdin(fstrace_settings *settings)
{
    char buf[UDS_READ_LENGTH];

    if (!read(STDIN_FILENO, buf, UDS_READ_LENGTH) > 0)
        return;

    for (int i = 0; i < UDS_READ_LENGTH; ++i)
    {
        if (buf[i] == 'q')
        {
            if (settings->debug)
                log_debug(settings->instance, "Received quit message");

            exit(RETURN_CODE_STOP);
        }
    }
}

static
bool read_inotify_event(fstrace_settings *settings, int inotifyfd,
                        const char *filter, char *last, check_fn_t check_fn)
{
    char buffer[BUF_LEN];
    int i = 0;
    int length = read(inotifyfd, buffer, BUF_LEN);

    if (length < 0)
        ERR_EXIT(settings->instance, "read(inotify)");

    while (i < length)
    {
        struct inotify_event *event = (struct inotify_event *) &buffer[i];

        if (event->mask & IN_Q_OVERFLOW)
        {
            log_error(settings->instance, "INotify queue overflow!");
            exit(EXIT_FAILURE);
        }

        if (event->mask & IN_DELETE_SELF)
        {
            log_error(settings->instance, "Watch directory deleted!");
            exit(EXIT_FAILURE);
        }

        if (event->len)
            if ((*check_fn)(settings, event->name, filter, last))
                return true;

        i += EVENT_SIZE + event->len;
    }

    return false;
}

static
void watch(fstrace_settings *settings, struct pollfd *fds, char *dir,
           char *filter, char *last, check_fn_t check_fn)
{
    bool done;

    if (!read_dir(settings, dir, filter, last, check_fn))
    {
        if (settings->debug)
            log_debug(settings->instance, "Waiting for event on '%s'.", dir);

        done = false;
        while (!done)
        {
            int retval = poll(fds, NFDS, -1);

            if (retval == -1)
                ERR_EXIT(settings->instance, "poll()");

            if (fds[STDIN_FDI].revents & POLLIN)
                read_stdin(settings);

            if (fds[STDIN_FDI].revents & POLLHUP)
                exit(EXIT_FAILURE);

            if (fds[INOTIFY_FDI].revents & POLLIN)
                if (read_inotify_event(settings, fds[INOTIFY_FDI].fd,
                                       filter, last, check_fn))
                    done = true;
        }
    }
}

static
void make_path(fstrace_settings *settings, char *path)
{
    char *ptr;
    long long instance_id;

    ptr = strrchr(settings->instance, '#');
    if (!ptr)
    {
        log_error(settings->instance, "Invalid instance.");
        exit(EXIT_FAILURE);
    }

    instance_id = strtoll(ptr + 1, NULL, 10);
    if ((!instance_id) ||
        (instance_id == LLONG_MIN) ||
        (instance_id == LLONG_MAX))
    {
        log_error(settings->instance, "Invalid instance id.");
        exit(EXIT_FAILURE);        
    }

    snprintf(path, PATH_MAX, "trace/%04X", instance_id % settings->num_shards);

    if (settings->debug)
        log_debug(settings->instance, "Watching path '%s' for '%s'.",
                  path, settings->instance);
}

static
void usage(int exit_status)
{
    FILE *out = NULL;

    if (exit_status == EXIT_SUCCESS)
        out = stdout;
    else
        out = stderr;

    fprintf(out,
       "usage: treadmill-fstrace [OPTIONS] <INSTANCE>\n"
       "\n"
       "  -h, --help            display this message and exit\n"
       "  -d, --debug           enables debug display\n"
       "  -z, --zk2fs           zk2fs path\n"
       "  -n, --num-shards      number of trace shards\n"
       "  -u, --use-sow         use trace sow databases\n"
       "  -s, --sow             trace sow databases path\n"
       "  -e, --service-exit    exit when the service exit event occurs\n"
    );

    exit(exit_status);
}

static
void parse_opts(int argc, char *argv[], fstrace_settings *settings)
{
    static const struct option longopts[] = {
        { "help", no_argument, 0, 'h' },
        { "debug", no_argument, 0, 'd' },
        { "zk2fs", required_argument, 0, 'z' },
        { "num-shards", required_argument, 0, 'n' },
        { "use-sow", no_argument, 0, 'u' },
        { "sow", required_argument, 0, 's' },
        { "service-exit", no_argument, 0, 'e' },
        { NULL, 0, 0, 0 }
    };
    int c;

    while ((c = getopt_long(argc, argv, "+hdz:n:us:e", longopts, NULL)) != -1)
    {
        switch (c)
        {
            case 'h':
                usage(EXIT_SUCCESS);
                break;
            case 'd':
                settings->debug = true;
                break;
            case 'z':
                settings->zk2fs = optarg;
                break;
            case 'n':
                settings->num_shards = atoi(optarg);
                break;
            case 'u':
                settings->use_sow = true;
                break;
            case 's':
                settings->sow = optarg;
                break;
            case 'e':
                settings->service_exit = true;
                break;
            default:
                usage(EXIT_FAILURE);
        }
    }

    if (optind + 1 > argc)
        usage(EXIT_FAILURE);

    settings->instance = argv[optind];
}

static
void check_settings(fstrace_settings *settings)
{
    if (!settings->zk2fs || !*settings->zk2fs)
    {
        log_error(settings->instance, "Missing option \"--zk2fs\".");
        exit(EXIT_FAILURE);
    }

    if (settings->num_shards <= 0)
    {
        log_error(settings->instance, "Number of trace shards must be > 0.");
        exit(EXIT_FAILURE);
    }

    if (settings->use_sow && (!settings->sow || !*settings->sow))
    {
        log_error(settings->instance, "Missing option \"--sow\".");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[])
{
    fstrace_settings settings;
    char path[PATH_MAX], dir[PATH_MAX], sow_dir[PATH_MAX];
    char db_filter[PATH_MAX], fs_filter[PATH_MAX];
    int inotifyfd, watchfd, watch_index;
    struct pollfd fds[NFDS];
    bool done;
    char last[NAME_MAX + 1] = "";

    memset(&settings, 0, sizeof(settings));
    settings.zk2fs = getenv("TREADMILL_SPAWN_ZK2FS");
    if (getenv("TREADMILL_SPAWN_ZK2FS_SHARDS"))
        settings.num_shards = atoi(getenv("TREADMILL_SPAWN_ZK2FS_SHARDS"));
    settings.sow = getenv("TREADMILL_SPAWN_ZK2FS_SOW");

    parse_opts(argc, argv, &settings);
    check_settings(&settings);

    printf("%s%s\n", INITIALIZE_PREFIX, settings.instance);

    inotifyfd = inotify_init();
    if (inotifyfd == -1)
        ERR_EXIT(settings.instance, "inotify_init");

    memset(&fds, 0, sizeof(fds));
    fds[STDIN_FDI] = (struct pollfd) { STDIN_FILENO, POLLIN | POLLHUP, 0 };
    fds[INOTIFY_FDI] = (struct pollfd) { inotifyfd, POLLIN, 0 };

    if (settings.debug)
        log_debug(settings.instance, "Waiting until ZK2FS dir is ready.");

    watchfd = inotify_add_watch(inotifyfd, settings.zk2fs, WATCH_MASK);

    if (watchfd == -1)
        ERR_EXIT(settings.instance, "inotify_add_watch(%s)", settings.zk2fs);

    watch(&settings, fds, settings.zk2fs, ".modified", NULL, check_file);
    inotify_rm_watch(inotifyfd, watchfd);

    make_path(&settings, path);
    join_path(dir, settings.zk2fs, path);

    if (settings.debug)
        log_debug(settings.instance, "Adding watch to '%s'.", dir);

    watchfd = inotify_add_watch(inotifyfd, dir, WATCH_MASK);

    if (watchfd == -1)
        ERR_EXIT(settings.instance, "inotify_add_watch(%s)", settings.zk2fs);

    done = false;

    if (settings.use_sow)
    {
        join_path(sow_dir, settings.zk2fs, settings.sow);
        snprintf(db_filter, PATH_MAX, "/%s/%s,", path, settings.instance);
        done = read_dir(&settings, sow_dir, db_filter, last, check_trace_db);
    }

    if (!done)
    {
        snprintf(fs_filter, PATH_MAX, "%s,", settings.instance);
        watch(&settings, fds, dir, fs_filter, last, check_trace_file);
    }

    inotify_rm_watch(inotifyfd, watchfd);

    close(inotifyfd);
    if (settings.debug)
        log_debug(settings.instance, "No more events to watch - done");

    return 0;
}
