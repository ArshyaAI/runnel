#ifndef RUNNEL_NATIVE_DARWIN_H
#define RUNNEL_NATIVE_DARWIN_H

#include <stdint.h>
#include <sys/types.h>

#define RUNNEL_PATH_MAX 4096

struct runnel_process_info {
    int32_t pid;
    int32_t ppid;
    uint32_t uid;
    uint32_t tty_device;
    int32_t tty_pgid;
    uint32_t has_tty;
    char tty_path[RUNNEL_PATH_MAX];
    uint64_t start_sec;
    uint64_t start_usec;
    uint64_t cpu_user_ns;
    uint64_t cpu_system_ns;
    uint64_t rss_bytes;
    uint64_t vms_bytes;
    uint32_t pidversion;
    uint64_t uniqueid;
    int32_t executable_errno;
    char executable[RUNNEL_PATH_MAX];
    int32_t cwd_errno;
    char cwd[RUNNEL_PATH_MAX];
};

struct runnel_fd_entry {
    int32_t fd;
    uint32_t kind;
    uint32_t open_flags;
    int64_t offset;
    uint64_t device;
    uint64_t inode;
    uint64_t size;
    int64_t mtime_sec;
    int64_t mtime_nsec;
    int32_t socket_family;
    int32_t socket_type;
    int32_t socket_protocol;
    int32_t socket_state;
    uint16_t local_port;
    uint16_t remote_port;
    int32_t detail_errno;
    char path[RUNNEL_PATH_MAX];
};

int runnel_list_pids(int32_t *pids, int capacity, int *truncated);
int runnel_have_listchildpids_symbol(void);
int runnel_list_child_pids(int32_t parent_pid, int32_t *pids, int capacity,
                           int *count);
int runnel_read_process(int32_t pid, struct runnel_process_info *out);
int runnel_read_identity(int32_t pid, struct runnel_process_info *out);
int runnel_procargs(int32_t pid, void *buffer, int capacity, int *used);
int runnel_list_fds(int32_t pid, struct runnel_fd_entry *entries, int capacity,
                    int *count, int *truncated);
int runnel_have_signal_symbol(void);
int runnel_signal_term(int32_t pid, uint32_t pidversion);
int runnel_pidpath_token(int32_t pid, uint32_t pidversion, char *path, int path_size);
int runnel_verify_static_code(const char *path, const char *requirement,
                              char *identifier, int identifier_size,
                              char *team, int team_size,
                              int32_t *status_out);

#endif
