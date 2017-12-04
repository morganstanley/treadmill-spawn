#include "treadmill-spawn-common.h"
#include <curl/curl.h>
#include <getopt.h>
#include <jansson.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef FSTRACE
#define FSTRACE "treadmill-fstrace"
#endif

#define MAX_RESPONSE      1024
#define MANIFEST_FILE     "data/manifest"

typedef struct {
    bool debug;
    char *id;
    char *name;
    char *cellapi_sock;
    char instance[MAX_INSTANCE_NAME + 1];
    bool service_exit;
} run_settings;

static
int connect_uds(run_settings *settings)
{
    struct sockaddr_un addr;
    int sockfd;

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;

    // starts at 1 because 0 indicates using the abstract namespace
    strncpy(&addr.sun_path[1], "/tms/", 5);
    strncpy(&addr.sun_path[6], settings->id, sizeof(addr.sun_path) - 7);

    if (settings->debug)
        log_debug(settings->id, "Connecting to UDS at '\\0%s'.",
                  &addr.sun_path[1]);

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd == -1)
        ERR_EXIT(settings->id, "socket()");

    if (connect(sockfd, (const struct sockaddr *) &addr,
                sizeof(struct sockaddr_un)) == -1)
        ERR_EXIT(settings->id, "connect(\\0%s)", &addr.sun_path[1]);

    return sockfd;
}

static
bool already_running(run_settings *settings)
{
    size_t read;
    FILE *fp = fopen(INSTANCE_FILE, "r");
    if (fp == NULL)
        return false;

    read = fread(settings->instance, sizeof(char), MAX_INSTANCE_NAME, fp);
    return read > 0;
}

static
void remove_timeout_file(run_settings *settings)
{
    const static char timeout_file[] = TIMEOUT_FILE;
    
    if (unlink(timeout_file) == -1 && errno != ENOENT)
        log_error(settings->id, "Failed to unlink(%s).", timeout_file);
}

static
size_t read_callback(void *bufptr, size_t size, size_t nitems, FILE *input)
{
    size_t read;
    read = fread(bufptr, size, nitems, input);
    return read;
}

static
size_t write_callback(void *bufptr, size_t size, size_t nitems, char *output)
{
    if (output[0] == '\0')
        strncpy(output, bufptr, MAX_RESPONSE);

    return size * nitems;
}

static
void write_instance(run_settings *settings)
{
    FILE *fp = fopen(INSTANCE_FILE, "w");
    if (fp == NULL)
        ERR_EXIT(settings->id, "fopen(%s)", INSTANCE_FILE);
    
    fputs(settings->instance, fp);
    fclose(fp);
}

static
bool parse_json(run_settings *settings, char *response)
{
    json_t *root, *instances, *instance;
    json_error_t error;

    root = json_loads(response, 0, &error);
    if(root == NULL)
    {
        log_error(settings->id, "Failed to read json '%s' on line %d: %s.",
                  response, error.line, error.text);
        json_decref(root);
        return false;
    }

    instances = json_object_get(root, "instances");
    if(!json_is_array(instances))
    {
        log_error(settings->id, "Instances is not an array '%s'.", MAX_ID,
                  response);
        json_decref(root);
        return false;
    }

    instance = json_array_get(instances, 0);
    if(!json_is_string(instance))
    {
        log_error(settings->id, "Invalid instance '%s'.", instance);
        json_decref(root);
        return false;
    }

    strncpy(settings->instance, json_string_value(instance), MAX_INSTANCE_NAME);

    if (settings->debug)
        log_debug(settings->id, "Created instance '%s'.", settings->instance);

    write_instance(settings);

    json_decref(root);
    return true;
}

static
bool create_instance(run_settings *settings)
{
    const static char instance_url[] = INSTANCE_URL;
    const static char manifest_file[] = MANIFEST_FILE;
    const static size_t instance_url_size = sizeof(instance_url);
    char url[instance_url_size + MAX_APP_NAME + 1];
    char response[MAX_RESPONSE + 1];
    long response_code = 0;
    struct stat file_info;
    struct curl_slist *headers = NULL;
    bool success = false;
    CURL *curl;
    CURLcode res;
    FILE *fp;

    memset(url, 0, sizeof(url));
    memset(response, 0, sizeof(response));

    strncpy(&url[0], instance_url, instance_url_size);
    /* the instance_url contains a null terminator */
    strncpy(&url[instance_url_size - 1], settings->name, MAX_APP_NAME);

    if (settings->debug)
        log_debug(settings->id, "HTTP POST '%s'.", url);

    if(stat(manifest_file, &file_info) == -1) 
        ERR_EXIT(settings->id, "stat(%s)", manifest_file);

    fp = fopen(manifest_file, "r");
    if(fp == NULL)
        ERR_EXIT(settings->id, "fopen(%s)", manifest_file);

    curl = curl_easy_init();
    if(curl == NULL)
        ERR_EXIT(settings->id, "curl_easy_init()");

    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Expect:");

    curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, settings->cellapi_sock);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
    curl_easy_setopt(curl, CURLOPT_READDATA, fp);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,
                     (curl_off_t) file_info.st_size);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response[0]);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 0L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 1800L); // 30 mins
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    res = curl_easy_perform(curl);

    if(res == CURLE_OK)
    {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

        if (response_code == 200)
            success = parse_json(settings, &response[0]);
        else
            log_error(settings->id, "Failed to create instance of '%s'.",
                      settings->name);
    }
    else
    {
        log_error(settings->id, "curl_easy_perform(%s -> %s) because %s",
                  settings->cellapi_sock, url, curl_easy_strerror(res));
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    fclose(fp);

    return success;
}

static
void create_instance_with_retry(run_settings *settings)
{
    bool created = false;
    int i = 0;
    while (i < API_RETRY)
    {
        if (settings->debug)
            log_debug(settings->id, "Create instance for '%s' attempt %d.",
                      settings->name, i + 1);

        if (create_instance(settings))
        {
            created = true;
            break;
        }

        i++;
    }

    if (!created)
    {
        log_error(settings->id, "Max retries exceeded %d.", API_RETRY);
        exit(EXIT_FAILURE);
    }
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
       "usage: treadmill-spawn-run [OPTIONS] <ID> <NAME>\n"
       "\n"
       "  -h, --help            display this message and exit\n"
       "  -d, --debug           display debug information\n"
       "  -a, --cellapi-sock    cell API socket\n"
       "  -e, --service-exit    exit when the service exit event occurs\n"
    );

    exit(exit_status);
}

static
void parse_opts(int argc, char *argv[], run_settings *settings)
{
    int index;

    static const struct option longopts[] = {
        { "help", no_argument, 0, 'h' },
        { "debug", no_argument, 0, 'd' },
        { "cellapi-sock", required_argument, 0, 'a' },
        { "service-exit", no_argument, 0, 'e' },
        { NULL, 0, 0, 0 }
    };
    int c;

    while ((c = getopt_long(argc, argv, "+hda:e", longopts, NULL)) != -1)
    {
        switch (c)
        {
            case 'h':
                usage(EXIT_SUCCESS);
                break;
            case 'd':
                settings->debug = true;
                break;
            case 'a':
                settings->cellapi_sock = optarg;
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
    settings->name = argv[index];
}

static
void check_settings(run_settings *settings)
{
    if (strlen(settings->id) > MAX_ID)
    {
        log_error(settings->id, "Max ID size can be %d.", MAX_ID);
        exit(EXIT_FAILURE);
    }

    if (strlen(settings->name) > MAX_APP_NAME)
    {
        log_error(settings->id, "Max app name (%s) size can be %d.",
                  settings->name, MAX_APP_NAME);
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
}

static
void redirect_to_uds(int sockfd)
{
    dup2(sockfd, STDIN_FILENO);
    dup2(sockfd, STDOUT_FILENO);
}

static
void exec_fstrace(run_settings *settings, bool use_sow)
{
    char *cmd[5] = { (char *) NULL };
    int rc = 0, pos = 0;

    cmd[pos++] = FSTRACE;

    if (use_sow)
        cmd[pos++] = "--use-sow";

    if (settings->service_exit)
        cmd[pos++] = "--service-exit";

    cmd[pos++] = settings->instance;

    if (settings->debug)
        log_debug(settings->id, 
            "Exec %s %s%s%s", FSTRACE,
            use_sow ? "--use-sow " : "",
            settings->service_exit ? "--service-exit " : "",
            settings->instance);

    if (execvp(FSTRACE, cmd) == -1)
        ERR_EXIT(settings->id, "execlp(%s)", cmd);
}

int main(int argc, char *argv[])
{
    run_settings settings;
    int sockfd;
    bool use_sow = false;

    memset(&settings, 0, sizeof(settings));
    settings.cellapi_sock = getenv("TREADMILL_SPAWN_CELLAPI_SOCK");
    parse_opts(argc, argv, &settings);
    check_settings(&settings);

    sockfd = connect_uds(&settings);

    remove_timeout_file(&settings);

    if (!already_running(&settings))
        create_instance_with_retry(&settings);
    else {
        if (settings.debug)
            log_debug(settings.id, "Instance is already running '%s'.",
                      settings.instance);
        use_sow = true;
    }

    redirect_to_uds(sockfd);

    exec_fstrace(&settings, use_sow);

    // Should never get here
    return EXIT_FAILURE;
}
