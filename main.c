#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define REPORT_FILE "reports.dat"
#define CONFIG_FILE "district.cfg"
#define LOG_FILE "logged_district"
#define LATEST_LINK "latest_report"
#define ACTIVE_PREFIX "active_reports-"
#define MONITOR_PID_FILE ".monitor_pid"

#define DIR_MODE 0750
#define REPORT_MODE 0664
#define CONFIG_MODE 0640
#define LOG_MODE 0644
#define DEFAULT_THRESHOLD 3

#define USER_LEN 64
#define CATEGORY_LEN 48
#define DESC_LEN 320

typedef enum { ROLE_BAD, ROLE_INSPECTOR, ROLE_MANAGER } Role;
typedef enum { CMD_NONE, CMD_ADD, CMD_REMOVE, CMD_LIST, CMD_SHOW, CMD_THRESHOLD, CMD_FILTER, CMD_METADATA, CMD_REMOVE_DISTRICT } Cmd;

typedef struct Report 
{
    uint32_t id;
    char inspector[USER_LEN];
    double latitude;
    double longitude;
    char category[CATEGORY_LEN];
    int32_t severity;
    time_t timestamp;
    char description[DESC_LEN];
    uint8_t active;
    uint8_t reserved[7];
} Report;

typedef struct AddData 
{
    char inspector[USER_LEN];
    double lat;
    double lon;
    char category[CATEGORY_LEN];
    int severity;
    char desc[DESC_LEN];
} AddData;

typedef struct Query 
{
    int active;
    int min_sev;
    int max_sev;
    unsigned int id;
    char inspector[USER_LEN];
    char category[CATEGORY_LEN];
    char text[DESC_LEN];
} Query;

void path_join(char *out, size_t size, const char *district, const char *file)
{
    snprintf(out, size, "%s/%s", district, file);
}

void path_active(char *out, size_t size, const char *district)
{
    snprintf(out, size, "%s%s", ACTIVE_PREFIX, district);
}

const char *role_name(Role role)
{
    if (role == ROLE_MANAGER) return "manager";
    if (role == ROLE_INSPECTOR) return "inspector";
    return "unknown";
}

Role parse_role(const char *s)
{
    if (strcmp(s, "manager") == 0) return ROLE_MANAGER;
    if (strcmp(s, "inspector") == 0) return ROLE_INSPECTOR;
    return ROLE_BAD;
}

int copy_text(char *dst, size_t size, const char *src, const char *name)
{
    if (snprintf(dst, size, "%s", src) >= (int)size) 
    {
        fprintf(stderr, "%s is too long\n", name);
        return -1;
    }
    return 0;
}

int good_name(const char *s, const char *what)
{
    int i;

    if (!s || !s[0]) 
    {
        fprintf(stderr, "%s must not be empty\n", what);
        return 0;
    }
    for (i = 0; s[i]; i++) 
    {
        if (!isalnum((unsigned char)s[i]) && s[i] != '_' && s[i] != '-') 
        {
            fprintf(stderr, "%s may contain only letters, digits, '_' and '-': %s\n", what, s);
            return 0;
        }
    }
    return 1;
}

int parse_uint(const char *s, unsigned int *out)
{
    char *end = NULL;
    unsigned long n;

    errno = 0;
    n = strtoul(s, &end, 10);
    if (errno || end == s || *end || n > 4294967295UL) return -1;
    *out = (unsigned int)n;
    return 0;
}

int parse_severity(const char *s, int *out)
{
    unsigned int n;

    if (parse_uint(s, &n) == -1 || n < 1 || n > 3) return -1;
    *out = (int)n;
    return 0;
}

int need_arg(int argc, char **argv, int i, const char *opt)
{
    if (i + 1 >= argc || strncmp(argv[i + 1], "--", 2) == 0) 
    {
        fprintf(stderr, "%s requires an argument\n", opt);
        return 0;
    }
    return 1;
}

void mode_string(mode_t mode, char out[11])
{
    out[0] = S_ISDIR(mode) ? 'd' : S_ISLNK(mode) ? 'l' : '-';
    out[1] = (mode & S_IRUSR) ? 'r' : '-';
    out[2] = (mode & S_IWUSR) ? 'w' : '-';
    out[3] = (mode & S_IXUSR) ? 'x' : '-';
    out[4] = (mode & S_IRGRP) ? 'r' : '-';
    out[5] = (mode & S_IWGRP) ? 'w' : '-';
    out[6] = (mode & S_IXGRP) ? 'x' : '-';
    out[7] = (mode & S_IROTH) ? 'r' : '-';
    out[8] = (mode & S_IWOTH) ? 'w' : '-';
    out[9] = (mode & S_IXOTH) ? 'x' : '-';
    out[10] = 0;
}

void time_string(time_t t, char *out, size_t size)
{
    struct tm tm;

    if (!localtime_r(&t, &tm)) 
    {
        snprintf(out, size, "unknown");
        return;
    }
    strftime(out, size, "%Y-%m-%d %H:%M:%S", &tm);
}

int check_access(const char *path, Role role, int r, int w, int x)
{
    struct stat st;
    int shift;
    int bits;
    char mode[11];

    if (stat(path, &st) == -1) 
    {
        perror(path);
        return -1;
    }

    shift = role == ROLE_MANAGER ? 6 : role == ROLE_INSPECTOR ? 3 : -1;
    bits = shift < 0 ? 0 : (st.st_mode >> shift) & 7;
    if ((!r || (bits & 4)) && (!w || (bits & 2)) && (!x || (bits & 1))) return 0;

    mode_string(st.st_mode, mode);
    fprintf(stderr, "permission denied for role=%s on %s: current mode %s (%03o)\n", role_name(role), path, mode, st.st_mode & 0777);
    return -1;
}

int ensure_layout(const char *district)
{
    char cfg[PATH_MAX], logp[PATH_MAX], buf[80];
    struct stat st;
    int fd, made, log_existed = 0;

    made = mkdir(district, DIR_MODE);
    if (made == -1 && errno != EEXIST) 
    {
        perror(district);
        return -1;
    }
    if (stat(district, &st) == -1 || !S_ISDIR(st.st_mode)) 
    {
        fprintf(stderr, "%s exists but is not a directory\n", district);
        return -1;
    }
    if (made == 0) chmod(district, DIR_MODE);

    path_join(cfg, sizeof(cfg), district, CONFIG_FILE);
    if (stat(cfg, &st) == -1) 
    {
        if (errno != ENOENT) 
        {
            perror(cfg);
            return -1;
        }
        fd = open(cfg, O_WRONLY | O_CREAT | O_TRUNC, CONFIG_MODE);
        if (fd == -1) 
        {
            perror(cfg);
            return -1;
        }
        fchmod(fd, CONFIG_MODE);
        snprintf(buf, sizeof(buf), "severity_threshold=%d\n", DEFAULT_THRESHOLD);
        write(fd, buf, strlen(buf));
        fsync(fd);
        close(fd);
        chmod(cfg, CONFIG_MODE);
    }

    path_join(logp, sizeof(logp), district, LOG_FILE);
    if (stat(logp, &st) == 0) log_existed = 1;
    fd = open(logp, O_WRONLY | O_CREAT | O_APPEND, LOG_MODE);
    if (fd == -1) 
    {
        perror(logp);
        return -1;
    }
    if (!log_existed) fchmod(fd, LOG_MODE);
    close(fd);
    if (!log_existed) chmod(logp, LOG_MODE);
    return 0;
}

int refresh_links(const char *district)
{
    char latest[PATH_MAX], active[PATH_MAX], target[PATH_MAX];
    struct stat st;

    path_join(latest, sizeof(latest), district, LATEST_LINK);
    unlink(latest);
    if (symlink(REPORT_FILE, latest) == -1) 
    {
        perror(latest);
        return -1;
    }

    path_active(active, sizeof(active), district);
    snprintf(target, sizeof(target), "%s/%s", district, REPORT_FILE);
    if (lstat(active, &st) == 0) 
    {
        if (!S_ISLNK(st.st_mode)) 
        {
            fprintf(stderr, "%s exists but is not a symbolic link\n", active);
            return -1;
        }
        if (stat(active, &st) == -1) fprintf(stderr, "warning: dangling symlink detected and replaced: %s\n", active);
        unlink(active);
    }
    if (symlink(target, active) == -1) 
    {
        perror(active);
        return -1;
    }
    return 0;
}

int read_threshold(const char *district, Role role, int *threshold)
{
    char cfg[PATH_MAX], buf[256];
    int fd;
    ssize_t n;
    char *p;

    *threshold = DEFAULT_THRESHOLD;
    if (ensure_layout(district) == -1) return -1;
    path_join(cfg, sizeof(cfg), district, CONFIG_FILE);
    if (check_access(cfg, role, 1, 0, 0) == -1) return -1;

    fd = open(cfg, O_RDONLY);
    if (fd == -1) 
    {
        perror(cfg);
        return -1;
    }
    n = read(fd, buf, sizeof(buf) - 1);
    if (n == -1) 
    {
        perror(cfg);
        close(fd);
        return -1;
    }
    close(fd);
    buf[n] = 0;

    p = strstr(buf, "severity_threshold=");
    if (p && (sscanf(p + strlen("severity_threshold="), "%d", threshold) != 1 || *threshold < 1 || *threshold > 3)) 
    {
        fprintf(stderr, "%s has invalid severity_threshold; expected 1, 2, or 3\n", cfg);
        return -1;
    }
    return 0;
}

int write_threshold(const char *district, Role role, int threshold)
{
    char cfg[PATH_MAX], buf[80], mode[11];
    struct stat st;
    int fd;

    if (ensure_layout(district) == -1) return -1;
    path_join(cfg, sizeof(cfg), district, CONFIG_FILE);

    if (stat(cfg, &st) == -1) 
    {
        perror(cfg);
        return -1;
    }
    if ((st.st_mode & 0777) != CONFIG_MODE) 
    {
        mode_string(st.st_mode, mode);
        fprintf(stderr, "district.cfg permission mismatch on %s: expected rw-r----- (640), found %s (%03o)\n", cfg, mode, st.st_mode & 0777);
        return -1;
    }
    if (check_access(cfg, role, 1, 1, 0) == -1) return -1;

    fd = open(cfg, O_WRONLY | O_TRUNC, CONFIG_MODE);
    if (fd == -1) 
    {
        perror(cfg);
        return -1;
    }
    snprintf(buf, sizeof(buf), "severity_threshold=%d\n", threshold);
    write(fd, buf, strlen(buf));
    fsync(fd);
    close(fd);
    printf("Set severity threshold for %s to %d\n", district, threshold);
    return 0;
}

int add_log(const char *district, Role role, const char *user, const char *action)
{
    char logp[PATH_MAX], line[512];
    int fd;

    if (ensure_layout(district) == -1) return -1;
    path_join(logp, sizeof(logp), district, LOG_FILE);
    if (check_access(logp, role, 0, 1, 0) == -1) 
    {
        fprintf(stderr, "operation log write refused for role=%s\n", role_name(role));
        return -1;
    }
    fd = open(logp, O_WRONLY | O_CREAT | O_APPEND, LOG_MODE);
    if (fd == -1) 
    {
        perror(logp);
        return -1;
    }
    snprintf(line, sizeof(line), "%lld %s %s %s\n",(long long)time(NULL), user, role_name(role), action);
    write(fd, line, strlen(line));
    fsync(fd);
    close(fd);
    return 0;
}

int report_fd(const char *district, int create, Role role, int want_write)
{
    char path[PATH_MAX];
    struct stat st;
    int existed = 0;
    int fd, flags;

    path_join(path, sizeof(path), district, REPORT_FILE);
    if (stat(path, &st) == 0) existed = 1;
    else if (errno != ENOENT)
     {
        perror(path);
        return -1;
     }

    if (!create && !existed) 
    {
        fprintf(stderr, "report store for %s does not exist\n", district);
        return -1;
    }
    if (existed && check_access(path, role, 1, want_write, 0) == -1) return -1;

    flags = want_write || create ? O_RDWR : O_RDONLY;
    if (create) flags |= O_CREAT;
    fd = open(path, flags, REPORT_MODE);
    if (fd == -1) 
    {
        perror(path);
        return -1;
    }
    if (!existed) 
    {
        fchmod(fd, REPORT_MODE);
        chmod(path, REPORT_MODE);
    }
    if (fstat(fd, &st) == -1 || st.st_size % (off_t)sizeof(Report) != 0) 
    {
        fprintf(stderr, "%s ended with a partial report record\n", path);
        close(fd);
        return -1;
    }
    return fd;
}

void print_report_info(const char *district)
{
    char path[PATH_MAX], mode[11], t[32];
    struct stat st;

    path_join(path, sizeof(path), district, REPORT_FILE);
    if (stat(path, &st) == -1) 
    {
        perror(path);
        return;
    }
    mode_string(st.st_mode, mode);
    time_string(st.st_mtime, t, sizeof(t));
    printf("reports.dat: permissions=%s size=%lld modified=%s\n", mode + 1, (long long)st.st_size, t);
}

int notify_monitor(const char *district, Role role, const char *user)
{
    int fd;
    char buf[32];
    ssize_t n;
    long monitor_pid;
    char logp[PATH_MAX];
    char line[512];
    int log_fd;
    const char *log_msg;

    fd = open(MONITOR_PID_FILE, O_RDONLY);

    if (fd == -1)
    {
        log_msg = "monitor_notify: FAILED - could not open .monitor_pid (monitor not running)";
        printf("monitor_reports not running, notification skipped\n");
        goto write_log;
    }

    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (n <= 0)
    {
        log_msg = "monitor_notify: FAILED - .monitor_pid is empty or unreadable";
        printf("monitor_reports PID file empty, notification skipped\n");
        goto write_log;
    }
    buf[n] = '\0';

    if (sscanf(buf, "%ld", &monitor_pid) != 1 || monitor_pid <= 0)
    {
        log_msg = "monitor_notify: FAILED - invalid PID in .monitor_pid";
        printf("monitor_reports PID invalid, notification skipped\n");
        goto write_log;
    }

    if (kill((pid_t)monitor_pid, SIGUSR1) == -1)
    {
        log_msg = "monitor_notify: FAILED - kill(SIGUSR1) failed (monitor may have stopped)";
        printf("monitor_reports could not be notified (signal failed)\n");
        goto write_log;
    }

    printf("monitor_reports notified (PID %ld)\n", monitor_pid);
    log_msg = "monitor_notify: OK - SIGUSR1 sent to monitor";

    write_log: 
    path_join(logp, sizeof(logp), district, LOG_FILE);
    log_fd = open(logp, O_WRONLY | O_CREAT | O_APPEND, LOG_MODE);
    if (log_fd != -1)
    {
        snprintf(line, sizeof(line), "%lld %s %s %s\n", (long long)time(NULL), user, role_name(role), log_msg);
        write(log_fd, line, strlen(line));
        fsync(log_fd);
        close(log_fd);
    }
    return 0;
}

int do_add(const char *district, AddData *in, Role role, unsigned int *new_id)
{
    Report r, old;
    uint32_t max_id = 0;
    int fd, threshold;
    ssize_t n;
    char t[32];

    if (read_threshold(district, role, &threshold) == -1) return -1;
    fd = report_fd(district, 1, role, 1);
    if (fd == -1) return -1;

    while ((n = read(fd, &old, sizeof(old))) == (ssize_t)sizeof(old)) 
    {
        if (old.id > max_id) max_id = old.id;
    }
    if (n != 0) 
    {
        fprintf(stderr, "report store ended with a partial record\n");
        close(fd);
        return -1;
    }

    memset(&r, 0, sizeof(r));
    r.id = max_id + 1;
    copy_text(r.inspector, sizeof(r.inspector), in->inspector, "inspector");
    r.latitude = in->lat;
    r.longitude = in->lon;
    copy_text(r.category, sizeof(r.category), in->category, "category");
    r.severity = in->severity;
    r.timestamp = time(NULL);
    copy_text(r.description, sizeof(r.description), in->desc, "description");
    r.active = 1;

    lseek(fd, 0, SEEK_END);
    if (write(fd, &r, sizeof(r)) != (ssize_t)sizeof(r)) 
    {
        perror("write report");
        close(fd);
        return -1;
    }
    fsync(fd);
    close(fd);
    if (refresh_links(district) == -1) return -1;

    *new_id = r.id;
    time_string(r.timestamp, t, sizeof(t));
    printf("Added report %u for %s\n", r.id, district);
    printf("Inspector: %s | Category: %s | Severity: %d | GPS: %.6f, %.6f | Created: %s\n", r.inspector, r.category, r.severity, r.latitude, r.longitude, t);
    if (r.severity >= threshold) 
    {
        printf("ESCALATION ALERT: severity %d reached threshold %d for %s\n", r.severity, threshold, district);
    }
    notify_monitor(district, role, in->inspector);
    return 0;
}

int do_remove(const char *district, unsigned int id, Role role)
{
    int fd, found = 0;
    struct stat st;
    off_t pos, next, end;
    Report r;

    fd = report_fd(district, 0, role, 1);
    if (fd == -1) return -1;
    if (fstat(fd, &st) == -1) 
    {
        perror("fstat");
        close(fd);
        return -1;
    }

    end = st.st_size;
    for (pos = 0; pos < end; pos += (off_t)sizeof(Report)) 
    {
        if (lseek(fd, pos, SEEK_SET) == (off_t)-1 || read(fd, &r, sizeof(r)) != (ssize_t)sizeof(r)) 
        {
            perror("read report");
            close(fd);
            return -1;
        }
        if (r.id == id) 
        {
            found = 1;
            break;
        }
    }
    if (!found) 
    {
        close(fd);
        fprintf(stderr, "report %u was not found in %s\n", id, district);
        return -1;
    }

    next = pos + (off_t)sizeof(Report);
    while (next < end) 
    {
        if (lseek(fd, next, SEEK_SET) == (off_t)-1 || read(fd, &r, sizeof(r)) != (ssize_t)sizeof(r) || lseek(fd, next - (off_t)sizeof(Report), SEEK_SET) == (off_t)-1 ||write(fd, &r, sizeof(r)) != (ssize_t)sizeof(r)) 
        {
            perror("shift report");
            close(fd);
            return -1;
        }
        next += (off_t)sizeof(Report);
    }

    ftruncate(fd, end - (off_t)sizeof(Report));
    fsync(fd);
    close(fd);
    printf("Removed report %u from %s\n", id, district);
    return 0;
}

int do_remove_district(const char *district, Role role)
{
    char active[PATH_MAX];
    char district_path[PATH_MAX];
    pid_t pid;
    int status;

    
    if (snprintf(district_path, sizeof(district_path), "%s", district) >= (int)sizeof(district_path))
     {
        fprintf(stderr, "district path too long\n");
        return -1;
     }

    
    struct stat st;
    if (stat(district_path, &st) == -1) 
    {
        fprintf(stderr, "district %s does not exist\n", district);
        return -1;
    }
    if (!S_ISDIR(st.st_mode))
     {
        fprintf(stderr, "%s is not a directory\n", district_path);
        return -1;
    }

    printf("Removing district directory: %s\n", district_path);

    pid = fork();
    if (pid == -1) 
    {
        perror("fork");
        return -1;
    }

    if (pid == 0) 
    {
        
        char *rm_argv[4];
        rm_argv[0] = "/bin/rm";
        rm_argv[1] = "-rf";
        rm_argv[2] = district_path;
        rm_argv[3] = NULL;

        execv("/bin/rm", rm_argv);
        
        perror("execv /bin/rm");
        _exit(1);
    }

     
    if (waitpid(pid, &status, 0) == -1)
     {
        perror("waitpid");
        return -1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) 
    {
        fprintf(stderr, "rm -rf failed for district %s (exit status %d)\n",
                district, WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        return -1;
    }
    printf("District directory %s removed successfully\n", district_path);

 
    path_active(active, sizeof(active), district);
    if (unlink(active) == -1) 
    {
        if (errno != ENOENT) 
        {
            perror(active);
            fprintf(stderr, "warning: could not remove symlink %s\n", active);
            
        }
    } 
    else 
    {
        printf("Removed symlink %s\n", active);
    }

    return 0;
}

void query_defaults(Query *q)
{
    memset(q, 0, sizeof(*q));
    q->active = 1;
    q->min_sev = -1;
    q->max_sev = -1;
}

int parse_query(const char *expr, Query *q)
{
    char buf[512], *tok, *v;
    int n;

    query_defaults(q);
    if (!expr) return 0;
    copy_text(buf, sizeof(buf), expr, "filter");
    for (tok = strtok(buf, ", "); tok; tok = strtok(NULL, ", ")) 
    {
        if (strncmp(tok, "severity:>=", 11) == 0) 
        {
            if (sscanf(tok + 11, "%d", &n) != 1) return -1;
            q->min_sev = n;
        } 
        else if (strncmp(tok, "severity>=", 10) == 0) 
        {
            if (sscanf(tok + 10, "%d", &n) != 1) return -1;
            q->min_sev = n;
        } 
        else if (strncmp(tok, "severity:<=", 11) == 0) 
        {
            if (sscanf(tok + 11, "%d", &n) != 1) return -1;
            q->max_sev = n;
        } 
        else if (strncmp(tok, "severity<=", 10) == 0) 
        {
            if (sscanf(tok + 10, "%d", &n) != 1) return -1;
            q->max_sev = n;
        } 
        else if (strncmp(tok, "severity:==", 11) == 0) 
        {
            if (sscanf(tok + 11, "%d", &n) != 1) return -1;
            q->min_sev = q->max_sev = n;
        } 
        else if (strncmp(tok, "severity=", 9) == 0)
        {
            if (sscanf(tok + 9, "%d", &n) != 1) return -1;
            q->min_sev = q->max_sev = n;
        } 
        else if (strncmp(tok, "category:==", 11) == 0) copy_text(q->category, sizeof(q->category), tok + 11, "category");
        else if (strncmp(tok, "category=", 9) == 0) copy_text(q->category, sizeof(q->category), tok + 9, "category");
        else if (strncmp(tok, "inspector:==", 12) == 0) copy_text(q->inspector, sizeof(q->inspector), tok + 12, "inspector");
        else if (strncmp(tok, "inspector=", 10) == 0) copy_text(q->inspector, sizeof(q->inspector), tok + 10, "inspector");
        else if (strncmp(tok, "text:==", 7) == 0) copy_text(q->text, sizeof(q->text), tok + 7, "text");
        else if (strncmp(tok, "text=", 5) == 0) copy_text(q->text, sizeof(q->text), tok + 5, "text");
        else if (strncmp(tok, "id=", 3) == 0) parse_uint(tok + 3, &q->id);
        else if (strncmp(tok, "active=", 7) == 0) 
        {
            v = tok + 7;
            if (strcmp(v, "all") == 0) q->active = -1;
            else q->active = (strcmp(v, "0") && strcmp(v, "false") && strcmp(v, "no"));
        } 
        else 
        {
            fprintf(stderr, "unknown filter term: %s\n", tok);
            return -1;
        }
    }
    return 0;
}

int contains(const char *hay, const char *needle)
{
    int i, j;

    if (!needle[0]) return 1;
    for (i = 0; hay[i]; i++) 
    {
        for (j = 0; needle[j] && hay[i + j] && tolower((unsigned char)hay[i + j]) == tolower((unsigned char)needle[j]); j++) 
        {
        }
        if (!needle[j]) return 1;
    }
    return 0;
}

int query_match(Report *r, Query *q)
{
    if (q->active != -1 && r->active != q->active) return 0;
    if (q->id && r->id != q->id) return 0;
    if (q->min_sev != -1 && r->severity < q->min_sev) return 0;
    if (q->max_sev != -1 && r->severity > q->max_sev) return 0;
    if (q->category[0] && strcmp(r->category, q->category)) return 0;
    if (q->inspector[0] && strcmp(r->inspector, q->inspector)) return 0;
    if (q->text[0] && !contains(r->description, q->text) && !contains(r->category, q->text) && !contains(r->inspector, q->text)) return 0;
    return 1;
}

void table_head(void)
{
    printf("%-5s %-3s %-6s %-19s %-14s %-10s %-11s %-11s %s\n", "ID", "Sev", "Active", "Timestamp", "Inspector", "Category", "Latitude", "Longitude", "Description");
}

void table_row(Report *r)
{
    char t[32];

    time_string(r->timestamp, t, sizeof(t));
    printf("%-5u %-3d %-6s %-19s %-14s %-10s %-11.6f %-11.6f %s\n", r->id, r->severity, r->active ? "yes" : "no", t, r->inspector, r->category, r->latitude, r->longitude, r->description);
}

int do_list(const char *district, Role role, Query *q)
{
    int fd, count = 0;
    Report r;
    ssize_t n;

    fd = report_fd(district, 0, role, 0);
    if (fd == -1) return -1;
    print_report_info(district);
    table_head();
    while ((n = read(fd, &r, sizeof(r))) == (ssize_t)sizeof(r)) 
    {
        if (query_match(&r, q)) 
        {
            table_row(&r);
            count++;
        }
    }
    close(fd);
    if (n != 0) return -1;
    printf("%d report(s)\n", count);
    return 0;
}

int cmp_int(long long a, const char *op, long long b)
{
    if (!strcmp(op, "=") || !strcmp(op, "==")) return a == b;
    if (!strcmp(op, "!=")) return a != b;
    if (!strcmp(op, "<")) return a < b;
    if (!strcmp(op, "<=")) return a <= b;
    if (!strcmp(op, ">")) return a > b;
    if (!strcmp(op, ">=")) return a >= b;
    return 0;
}

int cmp_str(const char *a, const char *op, const char *b)
{
    int c = strcmp(a, b);

    if (!strcmp(op, "=") || !strcmp(op, "==")) return c == 0;
    if (!strcmp(op, "!=")) return c != 0;
    if (!strcmp(op, "<")) return c < 0;
    if (!strcmp(op, "<=")) return c <= 0;
    if (!strcmp(op, ">")) return c > 0;
    if (!strcmp(op, ">=")) return c >= 0;
    return 0;
}

int parse_condition(const char *input, char *field, char *op, char *value)
{
    const char *p, *v;
    int i;
    const char *ops[] = {"==", "!=", "<=", ">=", "<", ">", "="};
    size_t len;

    p = strchr(input, ':');
    if (!p || p == input) return -1;
    len = (size_t)(p - input);
    if (len >= 32) return -1;

    memcpy(field, input, len);
    field[len] = 0;
    p++;

    for (i = 0; i < 7; i++) 
    {
        if (strncmp(p, ops[i], strlen(ops[i])) == 0) 
        {
            copy_text(op, 3, ops[i], "operator");
            v = p + strlen(ops[i]);
            if (*v == ':') v++;
            if (!*v || strlen(v) >= 320) return -1;
            copy_text(value, 320, v, "value");
            return 0;
        }
    }
    return -1;
}

int match_condition(Report *r, const char *field, const char *op, const char *value)
{
    int iv;
    long long tv;

    if (!strcmp(field, "severity")) 
    {
        if (sscanf(value, "%d", &iv) != 1) return 0;
        return cmp_int(r->severity, op, iv);
    }
    if (!strcmp(field, "timestamp")) 
    {
        if (sscanf(value, "%lld", &tv) != 1) return 0;
        return cmp_int((long long)r->timestamp, op, tv);
    }
    if (!strcmp(field, "category")) return cmp_str(r->category, op, value);
    if (!strcmp(field, "inspector")) return cmp_str(r->inspector, op, value);
    return 0;
}

int do_filter(const char *district, Role role, const char **conds, int cond_count)
{
    int fd, shown = 0, i, ok;
    Report r;
    ssize_t n;
    char fields[16][32], ops[16][3], values[16][320];

    if (cond_count < 1 || cond_count > 16) return -1;
    for (i = 0; i < cond_count; i++) 
    {
        if (parse_condition(conds[i], fields[i], ops[i], values[i]) == -1) 
        {
            fprintf(stderr, "invalid filter condition: %s\n", conds[i]);
            return -1;
        }
    }

    fd = report_fd(district, 0, role, 0);
    if (fd == -1) return -1;
    print_report_info(district);
    table_head();
    while ((n = read(fd, &r, sizeof(r))) == (ssize_t)sizeof(r)) 
    {
        if (!r.active) continue;
        ok = 1;
        for (i = 0; i < cond_count; i++) 
        {
            if (!match_condition(&r, fields[i], ops[i], values[i])) ok = 0;
        }
        if (ok) {
            table_row(&r);
            shown++;
        }
    }
    close(fd);
    if (n != 0) return -1;
    printf("%d report(s)\n", shown);
    return 0;
}

int do_show(const char *district, Role role, unsigned int id)
{
    int fd;
    Report r;
    char t[32];
    ssize_t n;

    fd = report_fd(district, 0, role, 0);
    if (fd == -1) return -1;
    while ((n = read(fd, &r, sizeof(r))) == (ssize_t)sizeof(r)) 
    {
        if (r.id == id) 
        {
            time_string(r.timestamp, t, sizeof(t));
            printf("ID: %u\nDistrict: %s\nInspector: %s\nGPS: %.6f, %.6f\nCategory: %s\nSeverity: %d\nTimestamp: %s\nDescription: %s\nActive: %s\n", r.id, district, r.inspector, r.latitude, r.longitude, r.category, r.severity, t, r.description, r.active ? "yes" : "no");
            close(fd);
            return 0;
        }
    }
    close(fd);
    if (n != 0) return -1;
    fprintf(stderr, "report %u was not found in %s\n", id, district);
    return -1;
}

void stat_line(const char *label, const char *path, int link)
{
    struct stat st;
    char mode[11], t[32];

    if ((link ? lstat(path, &st) : stat(path, &st)) == -1) 
    {
        if (errno == ENOENT) printf("%s: missing (%s)\n", label, path);
        else perror(path);
        return;
    }
    mode_string(st.st_mode, mode);
    time_string(st.st_mtime, t, sizeof(t));
    printf("%s: %s | size=%lld | mode=%s (%03o) | modified=%s\n", label, path, (long long)st.st_size, mode, st.st_mode & 0777, t);
}

int do_metadata(const char *district)
{
    char p[PATH_MAX], active[PATH_MAX], target[PATH_MAX];
    ssize_t n;
    struct stat st;

    stat_line("District directory", district, 0);
    path_join(p, sizeof(p), district, REPORT_FILE);
    stat_line("Binary reports", p, 0);
    path_join(p, sizeof(p), district, CONFIG_FILE);
    stat_line("Config", p, 0);
    path_join(p, sizeof(p), district, LOG_FILE);
    stat_line("Operation log", p, 0);
    path_join(p, sizeof(p), district, LATEST_LINK);
    stat_line("Report symlink", p, 1);
    n = readlink(p, target, sizeof(target) - 1);
    if (n != -1) 
    {
        target[n] = 0;
        printf("Report symlink target: %s\n", target);
    }
    path_active(active, sizeof(active), district);
    if (lstat(active, &st) == -1) printf("Active reports symlink: missing (%s)\n", active);
    else if (!S_ISLNK(st.st_mode)) printf("Active reports symlink: %s exists but is not a symlink\n", active);
    else 
    {
        n = readlink(active, target, sizeof(target) - 1);
        if (n != -1) 
        {
            target[n] = 0;
            printf("Active reports symlink: %s -> %s\n", active, target);
        }
        if (stat(active, &st) == -1) printf("warning: dangling symlink detected: %s\n", active);
    }
    return 0;
}

int prompt_line(const char *label, char *out, size_t size)
{
    printf("%s", label);
    fflush(stdout);
    if (!fgets(out, (int)size, stdin)) return -1;
    out[strcspn(out, "\r\n")] = 0;
    return 0;
}

int fill_missing_add_fields(AddData *a, int has_lat, int has_lon, int has_cat, int has_sev, int has_desc)
{
    char buf[DESC_LEN];

    if (!has_lat) 
    {
        if (prompt_line("Latitude: ", buf, sizeof(buf)) == -1 || sscanf(buf, "%lf", &a->lat) != 1) return -1;
    }
    if (!has_lon) 
    {
        if (prompt_line("Longitude: ", buf, sizeof(buf)) == -1 || sscanf(buf, "%lf", &a->lon) != 1) return -1;
    }
    if (!has_cat) 
    {
        if (prompt_line("Category (road/lighting/flooding/other): ", a->category, CATEGORY_LEN) == -1 || !good_name(a->category, "category")) return -1;
    }
    if (!has_sev) 
    {
        if (prompt_line("Severity level (1/2/3): ", buf, sizeof(buf)) == -1 || parse_severity(buf, &a->severity) == -1) return -1;
    }
    if (!has_desc) 
    {
        if (prompt_line("Description: ", a->desc, DESC_LEN) == -1) return -1;
    }
    return 0;
}

void usage(FILE *out)
{
    fprintf(out,
            "Usage:\n"
            "  city_manager --role inspector|manager --user USER --add DISTRICT [--lat LAT] [--lon LON] [--category CATEGORY] [--severity 1|2|3] [--description TEXT]\n"
            "  city_manager --role manager --user USER --remove_report DISTRICT ID\n"
            "  city_manager --role manager --user USER --remove_district DISTRICT\n"
            "  city_manager --role manager --user USER --update_threshold DISTRICT 1|2|3\n"
            "  city_manager --role inspector|manager --user USER --list DISTRICT\n"
            "  city_manager --role inspector|manager --user USER --view DISTRICT ID\n"
            "  city_manager --role inspector|manager --user USER --filter DISTRICT CONDITION...\n"
            "  city_manager --role inspector|manager --user USER --metadata DISTRICT\n");
}

int main(int argc, char **argv)
{
    Role role = ROLE_BAD;
    Cmd cmd = CMD_NONE;
    AddData add = {"unknown", 0, 0, "general", 1, "Report created from command line."};
    Query q;
    const char *district = NULL;
    const char *list_filter = NULL;
    const char *conds[16];
    int cond_count = 0;
    char user[USER_LEN] = "";
    char action[256] = "";
    unsigned int id = 0, made_id = 0;
    int threshold = 0;
    int has_lat = 0, has_lon = 0, has_cat = 0, has_sev = 0, has_desc = 0;
    int i, rc = -1;

    query_defaults(&q);
    if (argc == 1) 
    {
        usage(stderr);
        return 2;
    }

    for (i = 1; i < argc; i++) 
    {
        if (!strcmp(argv[i], "--help")) 
        {
            usage(stdout);
            return 0;
        }
        else if (!strcmp(argv[i], "--role")) 
        {
            if (!need_arg(argc, argv, i, "--role")) return 2;
            role = parse_role(argv[++i]);
            if (role == ROLE_BAD) 
            {
                fprintf(stderr, "unknown role: %s\n", argv[i]);
                return 2;
            }
        }
        else if (!strcmp(argv[i], "--user")) 
        {
            if (!need_arg(argc, argv, i, "--user")) return 2;
            if (!good_name(argv[i + 1], "user") || copy_text(user, sizeof(user), argv[++i], "--user") == -1) return 2;
        } 
        else if (!strcmp(argv[i], "--add")) 
        {
            if (cmd != CMD_NONE || !need_arg(argc, argv, i, "--add")) return 2;
            cmd = CMD_ADD;
            district = argv[++i];
        } 
        else if (!strcmp(argv[i], "--remove_report")) 
        {
            if (cmd != CMD_NONE || !need_arg(argc, argv, i, "--remove_report")) return 2;
            cmd = CMD_REMOVE;
            district = argv[++i];
            if (!need_arg(argc, argv, i, "--remove_report ID") || parse_uint(argv[++i], &id) == -1 || id == 0) return 2;
        } 
        else if (!strcmp(argv[i], "--remove_district")) 
        {
            if (cmd != CMD_NONE || !need_arg(argc, argv, i, "--remove_district")) return 2;
            cmd = CMD_REMOVE_DISTRICT;
            district = argv[++i];
        } 
        else if (!strcmp(argv[i], "--update_threshold") || !strcmp(argv[i], "--set_threshold"))
        {
            if (cmd != CMD_NONE || !need_arg(argc, argv, i, argv[i])) return 2;
            cmd = CMD_THRESHOLD;
            district = argv[++i];
            if (!need_arg(argc, argv, i, "--update_threshold VALUE") || parse_severity(argv[++i], &threshold) == -1) return 2;
        } 
        else if (!strcmp(argv[i], "--list")) 
        {
            if (cmd != CMD_NONE || !need_arg(argc, argv, i, "--list")) return 2;
            cmd = CMD_LIST;
            district = argv[++i];
        } 
        else if (!strcmp(argv[i], "--view") || !strcmp(argv[i], "--show")) 
        {
            if (cmd != CMD_NONE || !need_arg(argc, argv, i, argv[i])) return 2;
            cmd = CMD_SHOW;
            district = argv[++i];
            if (!need_arg(argc, argv, i, "--view ID") || parse_uint(argv[++i], &id) == -1 || id == 0) return 2;
        } 
        else if (!strcmp(argv[i], "--metadata")) 
        {
            if (cmd != CMD_NONE || !need_arg(argc, argv, i, "--metadata")) return 2;
            cmd = CMD_METADATA;
            district = argv[++i];
        } 
        else if (!strcmp(argv[i], "--filter")) 
        {
            if (cmd == CMD_LIST) 
            {
                if (!need_arg(argc, argv, i, "--filter")) return 2;
                list_filter = argv[++i];
            } 
            else 
            {
                if (cmd != CMD_NONE || !need_arg(argc, argv, i, "--filter")) return 2;
                cmd = CMD_FILTER;
                district = argv[++i];
                while (i + 1 < argc && strncmp(argv[i + 1], "--", 2)) 
                {
                    if (cond_count == 16) return 2;
                    conds[cond_count++] = argv[++i];
                }
                if (cond_count == 0) return 2;
            }
        } 
        else if (!strcmp(argv[i], "--lat")) 
        {
            if (!need_arg(argc, argv, i, "--lat") || sscanf(argv[++i], "%lf", &add.lat) != 1) return 2;
            has_lat = 1;
        } 
        else if (!strcmp(argv[i], "--lon")) 
        {
            if (!need_arg(argc, argv, i, "--lon") || sscanf(argv[++i], "%lf", &add.lon) != 1) return 2;
            has_lon = 1;
        } 
        else if (!strcmp(argv[i], "--category")) 
        {
            if (!need_arg(argc, argv, i, "--category") || !good_name(argv[i + 1], "category") ||
                copy_text(add.category, sizeof(add.category), argv[++i], "--category") == -1) return 2;
            has_cat = 1;
        } 
        else if (!strcmp(argv[i], "--severity")) 
        {
            if (!need_arg(argc, argv, i, "--severity") || parse_severity(argv[++i], &add.severity) == -1) return 2;
            has_sev = 1;
        } 
        else if (!strcmp(argv[i], "--description")) 
        {
            if (!need_arg(argc, argv, i, "--description") || copy_text(add.desc, sizeof(add.desc), argv[++i], "--description") == -1) return 2;
            has_desc = 1;
        } 
        else 
        {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            return 2;
        }
    }

    if (cmd == CMD_NONE || !district || !good_name(district, "district")) return 2;
    if (!user[0]) 
    {
        fprintf(stderr, "--user is required so actions can be written to logged_district\n");
        return 2;
    }
    if (role == ROLE_BAD) 
    {
        fprintf(stderr, "a valid --role is required: inspector or manager\n");
        return 2;
    }
    if ((cmd == CMD_REMOVE || cmd == CMD_THRESHOLD || cmd == CMD_REMOVE_DISTRICT) && role != ROLE_MANAGER) 
    {
        fprintf(stderr, "permission denied: this command requires role manager\n");
        return 1;
    }

    printf("Role: %s | User: %s\n", role_name(role), user);
    if (cmd == CMD_ADD) 
    {
        copy_text(add.inspector, sizeof(add.inspector), user, "--user");
        if (fill_missing_add_fields(&add, has_lat, has_lon, has_cat, has_sev, has_desc) == -1) return 2;
        rc = do_add(district, &add, role, &made_id);
        snprintf(action, sizeof(action), "add report_id=%u", made_id);
    } 
    else if (cmd == CMD_REMOVE) 
    {
        rc = do_remove(district, id, role);
        snprintf(action, sizeof(action), "remove_report report_id=%u", id);
    } 
    else if (cmd == CMD_REMOVE_DISTRICT) 
    {
        snprintf(action, sizeof(action), "remove_district district=%s", district);
        if (ensure_layout(district) != -1) 
        {
            add_log(district, role, user, action);
        }
        rc = do_remove_district(district, role);
        
        if (rc == 0) 
        {
            printf("District %s and its symlink removed.\n", district);
        }
        return rc == 0 ? 0 : 1;
    } 
    else if (cmd == CMD_LIST) 
    {
        if (parse_query(list_filter, &q) == -1) return 2;
        rc = do_list(district, role, &q);
        snprintf(action, sizeof(action), "list");
    } 
    else if (cmd == CMD_SHOW) 
    {
        rc = do_show(district, role, id);
        snprintf(action, sizeof(action), "show report_id=%u", id);
    } 
    else if (cmd == CMD_THRESHOLD) 
    {
        rc = write_threshold(district, role, threshold);
        snprintf(action, sizeof(action), "set_threshold threshold=%d", threshold);
    } 
    else if (cmd == CMD_FILTER) 
    {
        rc = do_filter(district, role, conds, cond_count);
        snprintf(action, sizeof(action), "filter");
    } 
    else if (cmd == CMD_METADATA) 
    {
        rc = do_metadata(district);
        snprintf(action, sizeof(action), "metadata");
    }

    if (rc == -1) return 1;
    if (add_log(district, role, user, action) == -1) 
    {
        fprintf(stderr, "operation succeeded, but logged_district was not updated for role=%s\n", role_name(role));
    }
    return 0;
}
