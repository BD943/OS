#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
 
#define MONITOR_PID_FILE ".monitor_pid"

#define PID_FILE_MODE 0644
 
static volatile sig_atomic_t stop_requested = 0;
 
static void signal_handler (int sig)
{
    if (sig == SIGUSR1) 
    {
        static const char message[] = "monitor_reports: new report added (SIGUSR1)\n";
        write(STDOUT_FILENO, message, sizeof(message) - 1);
    } 
    else if (sig == SIGINT) 
    {
        static const char message[] = "monitor_reports: SIGINT received, exiting\n";
        write(STDOUT_FILENO, message, sizeof(message) - 1);
        stop_requested = 1;
    }
}
 
static int install_handler(int sig)
{
    struct sigaction action;
 
    memset(&action, 0, sizeof(action));
    action.sa_handler = signal_handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    if (sigaction(sig, &action, NULL) == -1) 
    {
        perror("sigaction");
        return -1;
    }
    return 0;
}
 
static int write_pid_file(void)
{
    int fd;
    char buf[32];
    ssize_t len, written;
 
    fd = open(MONITOR_PID_FILE, O_WRONLY | O_CREAT | O_TRUNC, PID_FILE_MODE);
    if (fd == -1) 
    {
        perror(MONITOR_PID_FILE);
        return -1;
    }
 
    len = (ssize_t)snprintf(buf, sizeof(buf), "%ld\n", (long)getpid());
    written = write(fd, buf, (size_t)len);
    if (written != len) 
    {
        perror(MONITOR_PID_FILE);
        close(fd);
        return -1;
    }
    if (fsync(fd) == -1) 
    {
        perror(MONITOR_PID_FILE);
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}
 
int main(void)
{
    char buf[64];
 
    if (install_handler(SIGUSR1) == -1 || install_handler(SIGINT)  == -1 || write_pid_file() == -1) 
    {
        return 1;
    }
 
    snprintf(buf, sizeof(buf),"monitor_reports: PID %ld written to %s\n", (long)getpid(), MONITOR_PID_FILE);
    write(STDOUT_FILENO, buf, strlen(buf));
    while (!stop_requested) 
    {
        pause();
    }
 
    if (unlink(MONITOR_PID_FILE) == -1 && errno != ENOENT) 
    {
        perror(MONITOR_PID_FILE);
        return 1;
    }
 
    return 0;
}
