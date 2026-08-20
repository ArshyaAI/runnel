//go:build darwin && cgo

#include "native_darwin.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <libproc.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/sysctl.h>

// These stable private proc_info definitions are intentionally copied as a
// narrow ABI shim because the public SDK omits proc_info_private.h.
#define RUNNEL_PROC_PIDUNIQIDENTIFIERINFO 17
struct runnel_proc_uniqidentifierinfo {
    uint8_t uuid[16];
    uint64_t uniqueid;
    uint64_t parent_uniqueid;
    int32_t pidversion;
    int32_t original_parent_pidversion;
    uint64_t reserved2;
    uint64_t reserved3;
};
_Static_assert(sizeof(struct runnel_proc_uniqidentifierinfo) == 56,
               "proc unique identifier ABI changed");

typedef int (*runnel_signal_fn)(audit_token_t *, int);
typedef int (*runnel_pidpath_fn)(audit_token_t *, void *, uint32_t);
// Signature source: the active macOS SDK's <libproc.h>. Apple's XNU
// libproc.c wrapper returns a PID count for this function (unlike the byte
// count returned by the underlying proc_listpids call).
typedef int (*runnel_listchildpids_fn)(pid_t, void *, int);

static void *runnel_libproc;
static pthread_once_t runnel_libproc_once = PTHREAD_ONCE_INIT;
static void runnel_open_libproc(void) {
    runnel_libproc = dlopen("/usr/lib/libproc.dylib", RTLD_LAZY | RTLD_LOCAL);
}

static void *runnel_libproc_handle(void) {
    pthread_once(&runnel_libproc_once, runnel_open_libproc);
    return runnel_libproc;
}

static void *runnel_symbol(const char *name) {
    void *handle = runnel_libproc_handle();
    return handle == NULL ? NULL : dlsym(handle, name);
}

static audit_token_t runnel_token(int32_t pid, uint32_t pidversion) {
    audit_token_t token;
    memset(&token, 0, sizeof(token));
    // audit_token_t layout is the Darwin userspace/kernel ABI. The kernel
    // consumes target PID at val[5] and pidversion at val[7].
    token.val[5] = (uint32_t)pid;
    token.val[7] = pidversion;
    return token;
}

static uint64_t runnel_ticks_to_ns(uint64_t ticks) {
    mach_timebase_info_data_t info;
    if (mach_timebase_info(&info) != KERN_SUCCESS || info.denom == 0) {
        return 0;
    }
    __uint128_t value = (__uint128_t)ticks * info.numer / info.denom;
    return value > UINT64_MAX ? UINT64_MAX : (uint64_t)value;
}

static int runnel_unique_info(int32_t pid,
                              struct runnel_proc_uniqidentifierinfo *out) {
    memset(out, 0, sizeof(*out));
    errno = 0;
    int result = proc_pidinfo(pid, RUNNEL_PROC_PIDUNIQIDENTIFIERINFO, 0,
                              out, (int)sizeof(*out));
    if (result == (int)sizeof(*out)) {
        return 0;
    }
    return errno != 0 ? errno : ESRCH;
}

int runnel_list_pids(int32_t *pids, int capacity, int *truncated) {
    if (pids == NULL || capacity <= 0 || truncated == NULL) {
        return -EINVAL;
    }
    *truncated = 0;
    errno = 0;
    int returned = proc_listallpids(pids, capacity * (int)sizeof(*pids));
    if (returned <= 0) {
		return -(errno != 0 ? errno : EIO);
	}
	int count = returned;
    if (count >= capacity) {
        *truncated = 1;
        count = capacity;
    }
    return count;
}

int runnel_have_listchildpids_symbol(void) {
    return runnel_symbol("proc_listchildpids") != NULL;
}

int runnel_list_child_pids(int32_t parent_pid, int32_t *pids, int capacity,
                           int *count) {
    if (parent_pid <= 0 || pids == NULL || capacity <= 0 || count == NULL ||
        capacity > INT32_MAX / (int)sizeof(*pids)) {
        return EINVAL;
    }
    runnel_listchildpids_fn fn =
        (runnel_listchildpids_fn)runnel_symbol("proc_listchildpids");
    if (fn == NULL) {
        return ENOTSUP;
    }
    memset(pids, 0, (size_t)capacity * sizeof(*pids));
    errno = 0;
    int returned = fn((pid_t)parent_pid, pids,
                      capacity * (int)sizeof(*pids));
    // proc_listpids, which backs proc_listchildpids, converts a kernel -1 to
    // zero while preserving errno. Distinguish that failure from a genuine
    // empty child list after clearing errno immediately before the call.
    if (returned < 0 || (returned == 0 && errno != 0)) {
        return errno != 0 ? errno : EIO;
    }
    if (returned > capacity) {
        return EOVERFLOW;
    }
    *count = returned;
    return 0;
}

int runnel_pidpath_token(int32_t pid, uint32_t pidversion, char *path,
                         int path_size) {
    if (pid <= 0 || pidversion == 0 || path == NULL || path_size <= 1) {
        return EINVAL;
    }
    runnel_pidpath_fn fn = (runnel_pidpath_fn)runnel_symbol("proc_pidpath_audittoken");
    if (fn == NULL) {
        return ENOTSUP;
    }
    audit_token_t token = runnel_token(pid, pidversion);
    memset(path, 0, (size_t)path_size);
    errno = 0;
    int result = fn(&token, path, (uint32_t)path_size);
    if (result <= 0) {
        return errno != 0 ? errno : ESRCH;
    }
    path[path_size - 1] = '\0';
    return 0;
}

int runnel_read_process(int32_t pid, struct runnel_process_info *out) {
    if (pid <= 0 || out == NULL) {
        return EINVAL;
    }
    memset(out, 0, sizeof(*out));
    out->pid = pid;

    struct runnel_proc_uniqidentifierinfo before;
    int unique_error = runnel_unique_info(pid, &before);

    struct proc_taskallinfo info;
    memset(&info, 0, sizeof(info));
    errno = 0;
    int result = proc_pidinfo(pid, PROC_PIDTASKALLINFO, 0, &info,
                              (int)sizeof(info));
    if (result != (int)sizeof(info)) {
        return errno != 0 ? errno : ESRCH;
    }
    out->pid = (int32_t)info.pbsd.pbi_pid;
    out->ppid = (int32_t)info.pbsd.pbi_ppid;
    out->uid = (uint32_t)info.pbsd.pbi_uid;
    out->tty_device = info.pbsd.e_tdev;
    out->tty_pgid = (int32_t)info.pbsd.e_tpgid;
    out->has_tty = (info.pbsd.pbi_flags & PROC_FLAG_CONTROLT) != 0;
    if (out->has_tty) {
        char tty_name[256];
        if (devname_r((dev_t)info.pbsd.e_tdev, S_IFCHR, tty_name,
                      (int)sizeof(tty_name)) != NULL) {
            snprintf(out->tty_path, sizeof(out->tty_path), "/dev/%s", tty_name);
        }
    }
    out->start_sec = info.pbsd.pbi_start_tvsec;
    out->start_usec = info.pbsd.pbi_start_tvusec;
    out->cpu_user_ns = runnel_ticks_to_ns(info.ptinfo.pti_total_user);
    out->cpu_system_ns = runnel_ticks_to_ns(info.ptinfo.pti_total_system);
    out->rss_bytes = info.ptinfo.pti_resident_size;
    out->vms_bytes = info.ptinfo.pti_virtual_size;

    struct proc_vnodepathinfo paths;
    memset(&paths, 0, sizeof(paths));
    errno = 0;
    int cwd_result = proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &paths,
                                  (int)sizeof(paths));
    if (cwd_result == (int)sizeof(paths)) {
        strlcpy(out->cwd, paths.pvi_cdir.vip_path, sizeof(out->cwd));
    } else {
        out->cwd_errno = errno != 0 ? errno : EIO;
    }

    if (unique_error == 0) {
        out->pidversion = (uint32_t)before.pidversion;
        out->uniqueid = before.uniqueid;
        out->executable_errno = runnel_pidpath_token(pid, out->pidversion,
                                                      out->executable,
                                                      sizeof(out->executable));
    } else {
        out->executable_errno = unique_error;
		errno = 0;
		int path_result = proc_pidpath(pid, out->executable,
                                       (uint32_t)sizeof(out->executable));
        if (path_result <= 0) {
            out->executable_errno = errno != 0 ? errno : ESRCH;
        }
    }

    if (unique_error == 0) {
        struct runnel_proc_uniqidentifierinfo after;
        int after_error = runnel_unique_info(pid, &after);
        if (after_error != 0 || before.uniqueid != after.uniqueid ||
            before.pidversion != after.pidversion) {
            return ESRCH;
        }
    }
    return 0;
}

int runnel_read_identity(int32_t pid, struct runnel_process_info *out) {
    return runnel_read_process(pid, out);
}

int runnel_procargs(int32_t pid, void *buffer, int capacity, int *used) {
    if (pid <= 0 || buffer == NULL || capacity <= 0 || used == NULL) {
        return EINVAL;
    }
    int mib[3] = {CTL_KERN, KERN_PROCARGS2, pid};
    size_t size = (size_t)capacity;
    memset(buffer, 0, size);
    errno = 0;
    if (sysctl(mib, 3, buffer, &size, NULL, 0) != 0) {
        return errno != 0 ? errno : EIO;
    }
    if (size > (size_t)capacity || size > INT32_MAX) {
        return EOVERFLOW;
    }
    *used = (int)size;
    return 0;
}

int runnel_list_fds(int32_t pid, struct runnel_fd_entry *entries, int capacity,
                    int *count, int *truncated) {
    if (pid <= 0 || entries == NULL || capacity <= 0 || count == NULL ||
        truncated == NULL) {
        return EINVAL;
    }
    *count = 0;
    *truncated = 0;
    struct proc_fdinfo *fds = calloc((size_t)capacity, sizeof(*fds));
    if (fds == NULL) {
        return ENOMEM;
    }
	errno = 0;
	int bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds,
                             capacity * (int)sizeof(*fds));
	if (bytes == 0 && errno != 0) {
        int saved = errno != 0 ? errno : EIO;
        free(fds);
        return saved;
    }
    int n = bytes / (int)sizeof(*fds);
    if (n >= capacity) {
        n = capacity;
        *truncated = 1;
    }
    memset(entries, 0, (size_t)capacity * sizeof(*entries));
    for (int i = 0; i < n; i++) {
        entries[i].fd = fds[i].proc_fd;
        entries[i].kind = fds[i].proc_fdtype;
        if (fds[i].proc_fdtype == PROX_FDTYPE_VNODE) {
            struct vnode_fdinfowithpath vnode;
            memset(&vnode, 0, sizeof(vnode));
            errno = 0;
            int got = proc_pidfdinfo(pid, fds[i].proc_fd,
                                     PROC_PIDFDVNODEPATHINFO, &vnode,
                                     (int)sizeof(vnode));
            if (got == (int)sizeof(vnode)) {
                entries[i].open_flags = vnode.pfi.fi_openflags;
                entries[i].offset = vnode.pfi.fi_offset;
                entries[i].device = vnode.pvip.vip_vi.vi_stat.vst_dev;
                entries[i].inode = vnode.pvip.vip_vi.vi_stat.vst_ino;
                entries[i].size = vnode.pvip.vip_vi.vi_stat.vst_size;
                entries[i].mtime_sec = vnode.pvip.vip_vi.vi_stat.vst_mtime;
                entries[i].mtime_nsec = vnode.pvip.vip_vi.vi_stat.vst_mtimensec;
                strlcpy(entries[i].path, vnode.pvip.vip_path,
                        sizeof(entries[i].path));
            } else {
                entries[i].detail_errno = errno != 0 ? errno : EIO;
            }
        } else if (fds[i].proc_fdtype == PROX_FDTYPE_SOCKET) {
            struct socket_fdinfo socket;
            memset(&socket, 0, sizeof(socket));
            errno = 0;
            int got = proc_pidfdinfo(pid, fds[i].proc_fd,
                                     PROC_PIDFDSOCKETINFO, &socket,
                                     (int)sizeof(socket));
            if (got == (int)sizeof(socket)) {
                entries[i].open_flags = socket.pfi.fi_openflags;
                entries[i].offset = socket.pfi.fi_offset;
                entries[i].socket_family = socket.psi.soi_family;
                entries[i].socket_type = socket.psi.soi_type;
                entries[i].socket_protocol = socket.psi.soi_protocol;
                if (socket.psi.soi_kind == SOCKINFO_TCP) {
                    entries[i].socket_state = socket.psi.soi_proto.pri_tcp.tcpsi_state;
                    entries[i].local_port = ntohs((uint16_t)socket.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport);
                    entries[i].remote_port = ntohs((uint16_t)socket.psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport);
                }
            } else {
                entries[i].detail_errno = errno != 0 ? errno : EIO;
            }
        }
    }
    free(fds);
    *count = n;
    return 0;
}

int runnel_have_signal_symbol(void) {
    return runnel_symbol("proc_signal_with_audittoken") != NULL;
}

int runnel_signal_term(int32_t pid, uint32_t pidversion) {
    if (pid <= 0 || pidversion == 0) {
        return EINVAL;
    }
    runnel_signal_fn fn = (runnel_signal_fn)runnel_symbol("proc_signal_with_audittoken");
    if (fn == NULL) {
        return ENOTSUP;
    }
    audit_token_t token = runnel_token(pid, pidversion);
    errno = 0;
    if (fn(&token, SIGTERM) != 0) {
        return errno != 0 ? errno : EIO;
    }
    return 0;
}

static void runnel_copy_cfstring(CFStringRef value, char *out, int out_size) {
    if (out == NULL || out_size <= 0) {
        return;
    }
    out[0] = '\0';
    if (value != NULL) {
        (void)CFStringGetCString(value, out, out_size, kCFStringEncodingUTF8);
    }
}

int runnel_verify_static_code(const char *path, const char *requirement,
                              char *identifier, int identifier_size,
                              char *team, int team_size,
                              int32_t *status_out) {
    if (path == NULL || requirement == NULL || requirement[0] == '\0' ||
        status_out == NULL) {
        return EINVAL;
    }
    *status_out = errSecSuccess;
    if (identifier != NULL && identifier_size > 0) identifier[0] = '\0';
    if (team != NULL && team_size > 0) team[0] = '\0';

    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        kCFAllocatorDefault, (const UInt8 *)path, (CFIndex)strlen(path), false);
    if (url == NULL) {
        return EINVAL;
    }
    SecStaticCodeRef code = NULL;
    OSStatus status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
    CFRelease(url);
    if (status != errSecSuccess) {
        *status_out = status;
        return 0;
    }
    CFStringRef requirement_string = CFStringCreateWithCString(
        kCFAllocatorDefault, requirement, kCFStringEncodingUTF8);
    SecRequirementRef required = NULL;
    if (requirement_string == NULL) {
        CFRelease(code);
        return EINVAL;
    }
    status = SecRequirementCreateWithString(requirement_string,
                                             kSecCSDefaultFlags, &required);
    CFRelease(requirement_string);
    if (status == errSecSuccess) {
        SecCSFlags flags = kSecCSStrictValidate | kSecCSCheckAllArchitectures;
        status = SecStaticCodeCheckValidityWithErrors(code, flags, required, NULL);
    }
    if (status == errSecSuccess) {
        CFDictionaryRef info = NULL;
        status = SecCodeCopySigningInformation(code, kSecCSSigningInformation,
                                                &info);
        if (status == errSecSuccess && info != NULL) {
            runnel_copy_cfstring((CFStringRef)CFDictionaryGetValue(
                                     info, kSecCodeInfoIdentifier),
                                 identifier, identifier_size);
            runnel_copy_cfstring((CFStringRef)CFDictionaryGetValue(
                                     info, kSecCodeInfoTeamIdentifier),
                                 team, team_size);
            CFRelease(info);
        }
    }
    if (required != NULL) CFRelease(required);
    CFRelease(code);
    *status_out = status;
    return 0;
}
