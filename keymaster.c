#define FUSE_USE_VERSION 26

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <syslog.h>

#define ROOT_UID 0
#define ROOT_GID 0

#define KRB5CC_PREFIX_DIRNAME   "/tmp/"

#define KRB5CC_PREFIX           "krb5cc_"
#define KRB5CC_PREFIX_LEN       (sizeof(KRB5CC_PREFIX) - 1)

#define KRB5CC_FULL_PREFIX      KRB5CC_PREFIX_DIRNAME KRB5CC_PREFIX 
#define KRB5CC_FULL_PREFIX_LEN  (sizeof(KRB5CC_FULL_PREFIX) - 1)

static int g_allowed_pid = -1;

static int thread_id_to_process_id(pid_t tid, pid_t *pid) {
    char path[PATH_MAX], line[80];
    int i = -1;
    FILE *fp;

    snprintf(path, sizeof(path), "/proc/%d/status", tid);
    fp = fopen(path, "r");
    if (!fp)
        return -errno;
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "Pid:\t%d", &i) == 1) {
            break;
        }
    }
    fclose(fp);
    if (i == -1)
        return -ENOENT;
    *pid = i;
    return 0;
}

static int validate_request_pid(void) {
    int ret;
    pid_t pid;
    struct fuse_context *ctx;

    if (g_allowed_pid == -1) {
        return 0;
    }
    ctx = fuse_get_context();
    /* ctx->pid is a thread ID, not process ID. */
    ret = thread_id_to_process_id(ctx->pid, &pid);
    if (ret)
        return ret;
    return (pid == g_allowed_pid) ? 0 : -EACCES;
}

static int zsnprintf(char *out, size_t out_len, const char *fmt, ...) {
	int ret;
	va_list ap;
	va_start(ap, fmt);
	ret = vsnprintf(out, out_len, fmt, ap);
	va_end(ap);
	if (ret >= (int)out_len)
		return -ENAMETOOLONG;
	if (ret < 0)
		return ret;
	return 0;
}

static int uid_to_kpath(uid_t uid, char *out, size_t out_len) {
    return zsnprintf(out, out_len, KRB5CC_FULL_PREFIX "%d", uid);
}

static int fpath_to_uid(uid_t *uid, const char *path) {
    if (path[0] != '/') {
        return -ENOENT;
    }
    path++;
    if (strspn(path, "0123456789") != strlen(path)) {
        return -ENOENT;
    }
    *uid = atoi(path);
    return 0;
}

static int keymaster_getattr(const char *path, struct stat *s) {
    uid_t uid;
    int ret;
    char kpath[PATH_MAX];

    fprintf(stderr, "keymaster_getattr(path = '%s')\n", path);
    if ((path[0] == '/') && (path[1] == '\0')) {
        memset(s, 0, sizeof(struct stat));
        s->st_mode = S_IFDIR | 0500;
        s->st_nlink = 2;
        s->st_uid = ROOT_UID;
        s->st_gid = ROOT_GID;
        return 0;
    }
    ret = fpath_to_uid(&uid, path);
    if (ret)
        return ret;
    ret = uid_to_kpath(uid, kpath, sizeof(kpath));
    if (ret)
        return ret;
    ret = stat(kpath, s);
    if (ret) {
        return -errno;
    }
    return 0;
}

static int keymaster_statfs(const char *path, struct statvfs *s) {
    fprintf(stderr, "keymaster_statfs(path = '%s')\n", path);
    memset(s, 0, sizeof(struct statvfs));
    return 0;
}

static int keymaster_access(const char *path, int mask) {
    char kpath[PATH_MAX];
    int ret;
    uid_t uid;

    fprintf(stderr, "keymaster_access(path = '%s')\n", path);
    if (mask & W_OK)
        return -EPERM;
    if ((path[0] == '/') && (path[1] == '\0')) {
        return 0;
    }
    if (mask & X_OK)
        return -EPERM;
    ret = fpath_to_uid(&uid, path);
    if (ret)
        return ret;
    ret = uid_to_kpath(uid, kpath, sizeof(kpath));
    if (ret)
        return ret;
	ret = access(kpath, R_OK);
	if (ret == 0)
        return 0;
    ret = -errno;
	return ret;
}

static int keymaster_readdir(const char *path, void *buf,
        fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    int ret;
	DIR *dp;
	struct dirent *de;
    struct stat st;
    const char *p;
    char kpath[PATH_MAX];

    fprintf(stderr, "keymaster_readdir(path = '%s')\n", path);
	dp = opendir(KRB5CC_PREFIX_DIRNAME);
	if (!dp)
		return -errno;
	while ((de = readdir(dp))) {
        if (strncmp(de->d_name, KRB5CC_PREFIX, KRB5CC_PREFIX_LEN)) {
            continue;
        }
        p = de->d_name + KRB5CC_PREFIX_LEN;
        if (strspn(p, "0123456789") != strlen(p)) {
            continue;
        }
		memset(&st, 0, sizeof(st));
        if (zsnprintf(kpath, sizeof(kpath),
                      KRB5CC_PREFIX_DIRNAME "%s", de->d_name)) {
            continue;
        }
        ret = stat(kpath, &st);
        if (ret) {
            continue;
        }
		if (filler(buf, p, &st, 0)) {
			break;
        }
	}

	closedir(dp);
	return 0;
}

static int keymaster_open(const char *path, struct fuse_file_info *fi) {
	int ret;
    uid_t uid;
    char kpath[PATH_MAX];

    fprintf(stderr, "keymaster_open(path = '%s')\n", path);
    ret = validate_request_pid();
    if (ret)
        return ret;
    ret = fpath_to_uid(&uid, path);
    if (ret)
        return ret;
    ret = uid_to_kpath(uid, kpath, sizeof(kpath));
    if (ret)
        return ret;
	ret = open(kpath, O_RDONLY);
	if (ret < 0) {
        ret = -errno;
        return ret;
    }
    fi->fh = (uint64_t)ret;
	return 0;
}

static int keymaster_read(const char *path, char *buf, size_t size,
        off_t offset, struct fuse_file_info *fi) {
	int fd, ret;

    fprintf(stderr, "keymaster_read(path = '%s')\n", path);
    fd = (int)fi->fh;
	ret = pread(fd, buf, size, offset);
	if (ret < 0) {
		ret = -errno;
    }
	return ret;
}

static int keymaster_release(const char *path, struct fuse_file_info *fi)
{
    int fd;

    fprintf(stderr, "keymaster_release(path = '%s')\n", path);
    fd = (int)fi->fh;
    close(fd);
	return 0;
}

static struct fuse_operations keymaster_ops = {
    .getattr    = keymaster_getattr,
    .statfs     = keymaster_statfs,
	.access		= keymaster_access,
	.readdir	= keymaster_readdir,
	.open		= keymaster_open,
	.read		= keymaster_read,
	.release	= keymaster_release
};

int main(int argc, char *argv[]) {
    const char *k;

    k = getenv("KEYMASTER_PID");
    if (k) {
        if (strspn(k, "0123456789") != strlen(k)) {
            fprintf(stderr, "failed to parse KEYMASTER_PID: must be "
                    "a number");
            return 1;
        }
        g_allowed_pid = atoi(k);
    }
    fprintf(stderr, "keymaster starting\n");
	return fuse_main(argc, argv, &keymaster_ops, NULL);
}
