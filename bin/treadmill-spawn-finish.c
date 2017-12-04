#include "treadmill-spawn-common.h"
#include <curl/curl.h>
#include <getopt.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef S6SVC
#define S6SVC "s6-svc"
#endif

typedef struct {
    bool   debug;
    bool   has_instance;
    bool   stop;
    bool   reconnect;
    char   *id;
    char   *cellapi_sock;
    char   *cleanup;
    char   instance[MAX_INSTANCE_NAME + 1];
    int    return_code;
    double reconnect_timeout;
    time_t timeout_from;
} finish_settings;

static
void read_instance(finish_settings *settings)
{
    const static char instance_file[] = INSTANCE_FILE;
    FILE *fp = fopen(INSTANCE_FILE, "r");
    
    settings->has_instance = false;

    if (fp == NULL)
        return;

    if (fread(settings->instance, sizeof(char), MAX_INSTANCE_NAME, fp) > 0)
        settings->has_instance = true;

    if (settings->debug && settings->has_instance)
        log_debug(settings->id, "Using instance '%s'.", settings->instance);

    fclose(fp);
}

static
void touch(finish_settings *settings, const char *file)
{
    if (settings->debug)
        log_debug(settings->id, "Touching file '%s'.", file);

    FILE *fp = fopen(file, "wb");
    if (fp != NULL)
        fclose(fp);
}

static
void read_timeout_from(finish_settings *settings)
{
    const static char timeout_file[] = TIMEOUT_FILE;
    struct stat sb;

    if (stat(timeout_file, &sb) != -1)
    {
        settings->timeout_from = sb.st_mtime;

        if (settings->debug)
            log_debug(settings->id, "Timeout from %ld.",
                      settings->timeout_from);
    }
    else
    {
        if (errno == ENOENT)
            log_error(settings->id, "Failed to stat '%s'.", timeout_file);

        time(&settings->timeout_from);
        touch(settings, timeout_file);
    }
}


static
void remove_instance_file(finish_settings *settings)
{
    if (settings->debug)
        log_debug(settings->id, "Removing instance file.");

    unlink(INSTANCE_FILE);
    settings->has_instance = false;
}

static
bool delete_instance(finish_settings *settings)
{ 
    const static char instance_url[] = INSTANCE_URL;
    const static size_t instance_url_size = sizeof(instance_url);
    /* Need to replace # with %23 so 2 more chars */
    char url[instance_url_size + sizeof(settings->instance) + 2];
    char *sep;
    size_t pos;
    CURL *curl;
    CURLcode res;
    bool success = false;
    struct curl_slist *headers = NULL;
    long response_code = 0;

    memset(url, 0, sizeof(url));

    sep = strrchr(settings->instance, '#');
    if (sep == NULL)
    {
        log_error(settings->id, "URL '%s' does not contain a #.", url);
        exit(EXIT_FAILURE);
    }

    pos = (size_t)(sep - settings->instance);

    strncpy(&url[0], instance_url, instance_url_size);
    /* the instance_url contains a null terminator */
    strncpy(&url[instance_url_size - 1], settings->instance, pos);
    strncpy(&url[instance_url_size + pos - 1], "%23", 3);
    strncpy(&url[instance_url_size + pos + 2], &settings->instance[pos + 1],
            sizeof(settings->instance) - pos);

    if (settings->debug)
        log_debug(settings->id, "HTTP DELETE '%s'.", url);

    curl = curl_easy_init();
    if(curl == NULL)
        ERR_EXIT(settings->id, "curl_easy_init()");

    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, settings->cellapi_sock);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "delete");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 0L);

    res = curl_easy_perform(curl);

    if(res == CURLE_OK)
    {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

        if (response_code == 200)
            success = true;
        else
            log_error(settings->id, "Failed to delete instance '%s'.",
                      settings->instance);
    }
    else
    {
        log_error(settings->id, "curl_easy_perform(%s -> %s) because %s",
                  settings->cellapi_sock, url, curl_easy_strerror(res));
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return success;
}

static
void delete_instance_with_retry(finish_settings *settings)
{
    bool deleted = false;;
    int i = 0;
    while (i < API_RETRY)
    {
        if (settings->debug)
            log_debug(settings->id, "Delete instance '%s' attempt %d.",
                      settings->instance, i + 1);

        if (delete_instance(settings))
        {
            deleted = true;
            break;
        }

        i++;
    }

    if (!deleted)
    {
        log_error(settings->id, "Max retries exceeded %d.", API_RETRY);
        exit(EXIT_FAILURE);
    }
}

static
void stop(finish_settings *settings)
{ 
    if (!settings->has_instance)
        return;

    if (settings->debug)
        log_debug(settings->id, "Stopping with code %d.",
                  settings->return_code);

    if (settings->return_code != 0)
    {
        if (settings->return_code != RETURN_CODE_STOP && !settings->stop)
        {
            if (settings->debug)
                log_debug(settings->id, "Stop not specified or not %d.",
                          RETURN_CODE_STOP);

            return;
        }

        delete_instance_with_retry(settings);
    }

    remove_instance_file(settings);
}

static
void stop_supervisor(finish_settings *settings)
{
    if (settings->debug)
        log_debug(settings->id, "Stop supervisor '" S6SVC " -O .'.");

    system(S6SVC " -O .");
}

static
void cleanup(finish_settings *settings)
{
    size_t cleanup_size = strlen(settings->cleanup);
    size_t id_size = strlen(settings->id);
    char cleanup_path[cleanup_size + id_size + 2];

    memset(&cleanup_path, 0, sizeof(cleanup_path));

    strncpy(&cleanup_path[0], settings->cleanup, cleanup_size);
    strncpy(&cleanup_path[cleanup_size], "/", 1);
    strncpy(&cleanup_path[cleanup_size + 1], settings->id, id_size);

    touch(settings, cleanup_path);
}

static
bool should_remove(finish_settings *settings)
{
    if (settings->reconnect_timeout > 0)
    {
        time_t now = time(0);
        double seconds = difftime(now, settings->timeout_from);

        if (settings->debug)
            log_debug(settings->id, "Timeout from %f seconds ago (timeout %f).",
                      seconds, settings->reconnect_timeout);

        return seconds > settings->reconnect_timeout;
    }

    return false;
}

static
void finish(finish_settings *settings)
{
    if (settings->has_instance)
    {
        if (settings->reconnect && !should_remove(settings))
        {
            if (settings->debug)
                log_debug(settings->id, "Waiting for reconnect.");
            return;
        }

        remove_instance_file(settings);
    }

    stop_supervisor(settings);
    cleanup(settings);
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
        "usage: treadmill-spawn-finish [OPTIONS] <ID> <RC>\n"
        "\n"
        "  -h, --help            display this message and exit\n"
        "  -d, --debug           display debug information\n"
        "  -s, --stop            stop's even if RC is not \n"
        "  -r, --reconnect       do not cleanup when disconnected (with "
                                 "timeout in secs)\n"
        "  -a, --cellapi-sock    cell API socket\n"
        "  -c, --cleanup         cleanup directory\n"
    );

    exit(exit_status);
}

static
void parse_opts(int argc, char *argv[], finish_settings *settings)
{
    int index;

    static const struct option longopts[] = {
        { "help", no_argument, 0, 'h' },
        { "debug", no_argument, 0, 'd' },
        { "stop", no_argument, 0, 's' },
        { "reconnect", required_argument, 0, 'r' },
        { "cellapi-sock", required_argument, 0, 'a' },
        { "cleanup", required_argument, 0, 'c' },
        { NULL, 0, 0, 0 }
    };
    int c;

    while ((c = getopt_long(argc, argv, "+hdsr:a:c:", longopts, NULL)) != -1)
    {
        switch (c)
        {
            case 'h':
                usage(EXIT_SUCCESS);
                break;
            case 'd':
                settings->debug = true;
                break;
            case 's':
                settings->stop = true;
                break;
            case 'r':
                settings->reconnect = true;
                settings->reconnect_timeout = atof(optarg);
                break;
            case 'a':
                settings->cellapi_sock = optarg;
                break;
            case 'c':
                settings->cleanup = optarg;
                break;
            default:
                usage(EXIT_FAILURE);
        }
    }

    index = optind;
    if (index + 2 > argc)
        usage(EXIT_FAILURE);

    settings->id = argv[index++];
    settings->return_code = atof(argv[index]);
}

static
void check_settings(finish_settings *settings)
{
    struct stat sb = {0};

    if (strlen(settings->id) > MAX_ID)
    {
        log_error(settings->id, "Max ID size can be %d.", MAX_ID);
        exit(EXIT_FAILURE);
    }

    if (!settings->cellapi_sock || !*settings->cellapi_sock)
    {
        log_error(settings->id, "Missing option \"--cellapi-sock\".");
        exit(EXIT_FAILURE);
    }

    if (strlen(settings->cellapi_sock) > MAX_SOCKET)
    {
        log_error(settings->id, "Max socket (%s) size can be %d.",
                  settings->cellapi_sock, MAX_SOCKET);
        exit(EXIT_FAILURE);
    }

    if (!settings->cleanup || !*settings->cleanup)
    {
        log_error(settings->id, "Missing option \"--cleanup\".");
        exit(EXIT_FAILURE);
    }

    if (stat(settings->cleanup, &sb) == -1 || S_ISDIR(sb.st_mode) == 0)
    {
        log_error(settings->id, "Cleanup dir does not exist '%s'.",
                  settings->cleanup);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[])
{
    finish_settings settings;

    memset(&settings, 0, sizeof(settings));
    settings.cellapi_sock = getenv("TREADMILL_SPAWN_CELLAPI_SOCK");
    settings.cleanup = getenv("TREADMILL_SPAWN_CLEANUP");
    parse_opts(argc, argv, &settings);
    check_settings(&settings);

    read_instance(&settings);
    read_timeout_from(&settings);
    stop(&settings);
    finish(&settings);

    return EXIT_SUCCESS;
}
