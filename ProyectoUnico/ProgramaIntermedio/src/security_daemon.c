#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(__has_include)
#if !__has_include(<security/pam_appl.h>)
#error "PAM headers are required. Install libpam0g-dev to build security_daemon."
#endif
#endif

#include <security/pam_appl.h>

#define DEFAULT_PORT 8090
#define DEFAULT_MONITOR_INTERVAL 3
#define DEFAULT_SCAN_INTERVAL 5
#define MAX_TOP_PROCS 10
#define MAX_ALERTS 512
#define MAX_FILES 4096
#define MAX_THREATS 512
#define MAX_SIGNATURES 64
#define MAX_SESSIONS 128
#define MAX_REQ 65536
#define MAX_RESP 262144
#define MAX_PATH 1024
#define ALERT_DEDUP_WINDOW_SEC 12

#define SYS_NR_GET_PROCESS_INFO 548
#define SYS_NR_GET_SYSTEM_MONITOR 549
#define SYS_NR_FILE_ANALIZE 550
#define SYS_NR_SCAN_PROCESSES 551
#define SYS_NR_QUARANTINE_FILE 552
#define SYS_NR_RESTORE_FILE 553
#define SYS_NR_GET_QUARANTINE_LIST 554
#define SYS_NR_SIMULATE_PANIC 556

#define SYS_TOP_COMM_LEN 16
#define SYS_TOP_MAX 10
#define SYS_SCAN_MAX 128
#define SYS_QUARANTINE_MAX 128
#define SYS_Q_PATH_LEN 256

typedef struct {
    char comm[SYS_TOP_COMM_LEN];
    int pid;
    unsigned int mem_percent_x100;
} SysTopProcEntry;

typedef struct {
    unsigned long long mem_used_kb;
    unsigned long long mem_free_kb;
    unsigned long long mem_cache_kb;
    unsigned long long swap_used_kb;
    unsigned long long minor_faults;
    unsigned long long major_faults;
    unsigned long long pages_active;
    unsigned long long pages_inactive;
    unsigned int num_top_procs;
    SysTopProcEntry top_procs[SYS_TOP_MAX];
} SysSystemMonitorInfo;

typedef struct {
    char comm[SYS_TOP_COMM_LEN];
    int pid;
    unsigned long long exec_time_ns;
    unsigned long long mem_kb;
} SysProcessInfo;

typedef struct {
    unsigned long long size_bytes;
    unsigned long long mtime_sec;
    char sha256[65];
} SysFileAnalysisInfo;

typedef struct {
    int pid;
    char comm[SYS_TOP_COMM_LEN];
    unsigned long long rss_kb;
    unsigned long long minor_faults;
    unsigned long long major_faults;
} SysProcessScanEntry;

typedef struct {
    unsigned int count;
    SysProcessScanEntry entries[SYS_SCAN_MAX];
} SysProcessScanResult;

typedef struct {
    char path[SYS_Q_PATH_LEN];
    unsigned long long quarantined_at_sec;
} SysQuarantineEntry;

typedef struct {
    unsigned int count;
    SysQuarantineEntry entries[SYS_QUARANTINE_MAX];
} SysQuarantineList;

typedef struct {
    char nombre[32];
    int pid;
    double porcentaje;
} TopProc;

typedef struct {
    unsigned long memoria_usada;
    unsigned long memoria_libre;
    unsigned long memoria_cache;
    unsigned long swap_usada;
    unsigned long fallos_menores;
    unsigned long fallos_mayores;
    unsigned long paginas_activas;
    unsigned long paginas_inactivas;
    TopProc top[MAX_TOP_PROCS];
    int top_count;
} Metrics;

typedef struct {
    char tipo[16];
    char severidad[8];
    char descripcion[256];
    char timestamp[32];
    time_t epoch_sec;
} Alert;

typedef struct {
    char path[MAX_PATH];
    char hash[65];
    long mtime;
    char estado[16];
    char timestamp[32];
} FileRecord;

typedef struct {
    char hash[65];
    char nombre[80];
    char severidad[8];
    char descripcion[180];
} Signature;

typedef struct {
    char nombre[80];
    char archivo[MAX_PATH];
    char severidad[8];
    char descripcion[180];
    char timestamp[32];
} ThreatEvent;

typedef struct {
    char token[65];
    char username[64];
    char role[16];
    time_t created;
    int active;
} Session;

typedef struct {
    pthread_mutex_t lock;
    Metrics metrics;
    Alert alerts[MAX_ALERTS];
    int alert_count;
    FileRecord files[MAX_FILES];
    int file_count;
    Signature signatures[MAX_SIGNATURES];
    int signature_count;
    ThreatEvent threats[MAX_THREATS];
    int threat_count;
    Session sessions[MAX_SESSIONS];
    char restored_paths[MAX_FILES][MAX_PATH];
    int restored_count;
    int scan_enabled;
} AppState;

static AppState g_state = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .scan_enabled = 1,
};

static volatile sig_atomic_t g_running = 1;
static int g_server_fd = -1;
static int g_monitor_interval = DEFAULT_MONITOR_INTERVAL;
static int g_scan_interval = DEFAULT_SCAN_INTERVAL;
static int g_port = DEFAULT_PORT;
static int g_daemon_mode = 0;
static char g_watch_dir[MAX_PATH] = "/tmp/project_scan";
static char g_blacklist_path[MAX_PATH] = "./data/hash_blacklist.json";

static void now_string(char *out, size_t out_sz) {
    time_t t = time(NULL);
    struct tm tm_now;
    localtime_r(&t, &tm_now);
    strftime(out, out_sz, "%Y-%m-%d %H:%M:%S", &tm_now);
}

static void auth_debug_log(const char *fmt, ...) {
    FILE *f = fopen("/tmp/security_daemon_auth.log", "a");
    if (!f) {
        return;
    }

    char ts[32];
    now_string(ts, sizeof(ts));
    fprintf(f, "[%s] ", ts);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);

    fputc('\n', f);
    fclose(f);
}

static void epoch_string(unsigned long long sec, char *out, size_t out_sz) {
    if (sec == 0) {
        out[0] = '\0';
        return;
    }

    time_t t = (time_t)sec;
    struct tm tm_now;
    localtime_r(&t, &tm_now);
    strftime(out, out_sz, "%Y-%m-%d %H:%M:%S", &tm_now);
}

static void trim_newline(char *s) {
    if (!s) {
        return;
    }
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[n - 1] = '\0';
        n--;
    }
}

static int is_number_str(const char *s) {
    if (!s || !*s) {
        return 0;
    }
    for (size_t i = 0; s[i]; i++) {
        if (s[i] < '0' || s[i] > '9') {
            return 0;
        }
    }
    return 1;
}

static void json_escape(const char *in, char *out, size_t out_sz) {
    size_t j = 0;
    for (size_t i = 0; in && in[i] && j + 2 < out_sz; i++) {
        char c = in[i];
        if (c == '"' || c == '\\') {
            out[j++] = '\\';
            out[j++] = c;
        } else if ((unsigned char)c < 32) {
            out[j++] = ' ';
        } else {
            out[j++] = c;
        }
    }
    out[j] = '\0';
}

static int kcall_get_system_monitor(SysSystemMonitorInfo *info) {
    if (!info) {
        errno = EINVAL;
        return -1;
    }
    return syscall(SYS_NR_GET_SYSTEM_MONITOR, info) < 0 ? -1 : 0;
}

static int kcall_get_process_info(int pid, SysProcessInfo *info) {
    if (pid <= 0 || !info) {
        errno = EINVAL;
        return -1;
    }
    return syscall(SYS_NR_GET_PROCESS_INFO, pid, info) < 0 ? -1 : 0;
}

static int kcall_file_analize(const char *path, SysFileAnalysisInfo *info) {
    if (!path || !info) {
        errno = EINVAL;
        return -1;
    }
    return syscall(SYS_NR_FILE_ANALIZE, path, info) < 0 ? -1 : 0;
}

static int kcall_scan_processes(SysProcessScanResult *res) {
    if (!res) {
        errno = EINVAL;
        return -1;
    }
    return syscall(SYS_NR_SCAN_PROCESSES, res) < 0 ? -1 : 0;
}

static int kcall_quarantine_file(const char *path) {
    if (!path) {
        errno = EINVAL;
        return -1;
    }
    return syscall(SYS_NR_QUARANTINE_FILE, path) < 0 ? -1 : 0;
}

static int kcall_restore_file(const char *path) {
    if (!path) {
        errno = EINVAL;
        return -1;
    }
    return syscall(SYS_NR_RESTORE_FILE, path) < 0 ? -1 : 0;
}

static int kcall_get_quarantine_list(SysQuarantineList *list) {
    if (!list) {
        errno = EINVAL;
        return -1;
    }
    return syscall(SYS_NR_GET_QUARANTINE_LIST, list) < 0 ? -1 : 0;
}

static unsigned long read_vmstat_value(const char *key) {
    FILE *f = fopen("/proc/vmstat", "r");
    if (!f) {
        return 0;
    }

    char k[128];
    unsigned long v;
    while (fscanf(f, "%127s %lu", k, &v) == 2) {
        if (strcmp(k, key) == 0) {
            fclose(f);
            return v;
        }
    }

    fclose(f);
    return 0;
}

static unsigned long read_meminfo_value(const char *key) {
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) {
        return 0;
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char k[64];
        unsigned long v;
        if (sscanf(line, "%63[^:]: %lu kB", k, &v) == 2) {
            if (strcmp(k, key) == 0) {
                fclose(f);
                return v;
            }
        }
    }

    fclose(f);
    return 0;
}

static void reset_top(TopProc *top, int *count) {
    *count = 0;
    for (int i = 0; i < MAX_TOP_PROCS; i++) {
        top[i].pid = 0;
        top[i].porcentaje = 0.0;
        top[i].nombre[0] = '\0';
    }
}

static void sort_top(TopProc *top, int count) {
    for (int i = 0; i < count; i++) {
        for (int j = i + 1; j < count; j++) {
            if (top[j].porcentaje > top[i].porcentaje) {
                TopProc t = top[i];
                top[i] = top[j];
                top[j] = t;
            }
        }
    }
}

static void maybe_insert_top(TopProc *top, int *count, const char *name, int pid, double pct) {
    if (*count < MAX_TOP_PROCS) {
        snprintf(top[*count].nombre, sizeof(top[*count].nombre), "%s", name);
        top[*count].pid = pid;
        top[*count].porcentaje = pct;
        (*count)++;
        return;
    }

    int min_idx = 0;
    for (int i = 1; i < *count; i++) {
        if (top[i].porcentaje < top[min_idx].porcentaje) {
            min_idx = i;
        }
    }

    if (pct > top[min_idx].porcentaje) {
        snprintf(top[min_idx].nombre, sizeof(top[min_idx].nombre), "%s", name);
        top[min_idx].pid = pid;
        top[min_idx].porcentaje = pct;
    }
}

static void collect_metrics(Metrics *m) {
    SysSystemMonitorInfo km;
    memset(&km, 0, sizeof(km));

    if (kcall_get_system_monitor(&km) == 0) {
        m->memoria_usada = (unsigned long)km.mem_used_kb;
        m->memoria_libre = (unsigned long)km.mem_free_kb;
        m->memoria_cache = (unsigned long)km.mem_cache_kb;
        m->swap_usada = (unsigned long)km.swap_used_kb;
        m->fallos_menores = (unsigned long)km.minor_faults;
        m->fallos_mayores = (unsigned long)km.major_faults;
        m->paginas_activas = (unsigned long)km.pages_active;
        m->paginas_inactivas = (unsigned long)km.pages_inactive;

        reset_top(m->top, &m->top_count);
        int lim = (int)km.num_top_procs;
        if (lim > MAX_TOP_PROCS) {
            lim = MAX_TOP_PROCS;
        }
        for (int i = 0; i < lim; i++) {
            snprintf(m->top[i].nombre, sizeof(m->top[i].nombre), "%s", km.top_procs[i].comm);
            m->top[i].pid = km.top_procs[i].pid;
            m->top[i].porcentaje = (double)km.top_procs[i].mem_percent_x100 / 100.0;
        }
        m->top_count = lim;
        sort_top(m->top, m->top_count);
        return;
    }

    unsigned long mem_total = read_meminfo_value("MemTotal");
    unsigned long mem_free = read_meminfo_value("MemFree");
    unsigned long mem_buffers = read_meminfo_value("Buffers");
    unsigned long mem_cached = read_meminfo_value("Cached");
    unsigned long swap_total = read_meminfo_value("SwapTotal");
    unsigned long swap_free = read_meminfo_value("SwapFree");
    unsigned long active_anon = read_meminfo_value("Active(anon)");
    unsigned long active_file = read_meminfo_value("Active(file)");
    unsigned long inactive_anon = read_meminfo_value("Inactive(anon)");
    unsigned long inactive_file = read_meminfo_value("Inactive(file)");

    unsigned long used = 0;
    if (mem_total > mem_free + mem_buffers + mem_cached) {
        used = mem_total - mem_free - mem_buffers - mem_cached;
    }

    m->memoria_usada = used;
    m->memoria_libre = mem_free;
    m->memoria_cache = mem_cached;
    m->swap_usada = (swap_total > swap_free) ? (swap_total - swap_free) : 0;
    m->fallos_menores = read_vmstat_value("pgfault");
    m->fallos_mayores = read_vmstat_value("pgmajfault");
    m->paginas_activas = active_anon + active_file;
    m->paginas_inactivas = inactive_anon + inactive_file;

    reset_top(m->top, &m->top_count);

    DIR *d = opendir("/proc");
    if (!d) {
        return;
    }

    long page_kb = sysconf(_SC_PAGESIZE) / 1024;
    if (page_kb <= 0) {
        page_kb = 4;
    }

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (!is_number_str(ent->d_name)) {
            continue;
        }

        int pid = atoi(ent->d_name);
        char path_statm[128];
        char path_comm[128];
        snprintf(path_statm, sizeof(path_statm), "/proc/%d/statm", pid);
        snprintf(path_comm, sizeof(path_comm), "/proc/%d/comm", pid);

        FILE *f_statm = fopen(path_statm, "r");
        if (!f_statm) {
            continue;
        }

        unsigned long size_pages = 0, rss_pages = 0;
        if (fscanf(f_statm, "%lu %lu", &size_pages, &rss_pages) != 2) {
            fclose(f_statm);
            continue;
        }
        fclose(f_statm);

        FILE *f_comm = fopen(path_comm, "r");
        if (!f_comm) {
            continue;
        }

        char comm[32];
        if (!fgets(comm, sizeof(comm), f_comm)) {
            fclose(f_comm);
            continue;
        }
        fclose(f_comm);
        trim_newline(comm);

        unsigned long rss_kb = rss_pages * (unsigned long)page_kb;
        double pct = 0.0;
        if (mem_total > 0) {
            pct = (double)rss_kb * 100.0 / (double)mem_total;
        }

        maybe_insert_top(m->top, &m->top_count, comm, pid, pct);
    }
    closedir(d);

    sort_top(m->top, m->top_count);
}

static void push_alert(const char *tipo, const char *sev, const char *desc) {
    pthread_mutex_lock(&g_state.lock);

    time_t now_sec = time(NULL);

    for (int i = g_state.alert_count - 1; i >= 0; i--) {
        Alert *prev = &g_state.alerts[i];
        if (prev->epoch_sec == 0) {
            continue;
        }

        if ((now_sec - prev->epoch_sec) > ALERT_DEDUP_WINDOW_SEC) {
            break;
        }

        if (strcmp(prev->tipo, tipo) == 0 &&
            strcmp(prev->severidad, sev) == 0 &&
            strcmp(prev->descripcion, desc) == 0) {
            pthread_mutex_unlock(&g_state.lock);
            return;
        }
    }

    if (g_state.alert_count >= MAX_ALERTS) {
        memmove(&g_state.alerts[0], &g_state.alerts[1], sizeof(Alert) * (MAX_ALERTS - 1));
        g_state.alert_count = MAX_ALERTS - 1;
    }

    Alert *a = &g_state.alerts[g_state.alert_count++];
    snprintf(a->tipo, sizeof(a->tipo), "%s", tipo);
    snprintf(a->severidad, sizeof(a->severidad), "%s", sev);
    snprintf(a->descripcion, sizeof(a->descripcion), "%s", desc);
    now_string(a->timestamp, sizeof(a->timestamp));
    a->epoch_sec = now_sec;

    pthread_mutex_unlock(&g_state.lock);
}

static void push_threat(const char *nombre, const char *archivo, const char *sev, const char *desc) {
    pthread_mutex_lock(&g_state.lock);

    if (g_state.threat_count >= MAX_THREATS) {
        memmove(&g_state.threats[0], &g_state.threats[1], sizeof(ThreatEvent) * (MAX_THREATS - 1));
        g_state.threat_count = MAX_THREATS - 1;
    }

    ThreatEvent *t = &g_state.threats[g_state.threat_count++];
    snprintf(t->nombre, sizeof(t->nombre), "%s", nombre);
    snprintf(t->archivo, sizeof(t->archivo), "%s", archivo);
    snprintf(t->severidad, sizeof(t->severidad), "%s", sev);
    snprintf(t->descripcion, sizeof(t->descripcion), "%s", desc);
    now_string(t->timestamp, sizeof(t->timestamp));

    pthread_mutex_unlock(&g_state.lock);
}

static void try_simulate_panic(const char *msg) {
    long ret = syscall(SYS_NR_SIMULATE_PANIC, msg);
    if (ret < 0 && errno == ENOSYS) {
        /* Kernel syscall may not be present yet during early development. */
        return;
    }
}

static void *monitor_thread(void *arg) {
    (void)arg;
    unsigned long prev_major = 0;
    int high_streak = 0;

    while (g_running) {
        Metrics m;
        SysProcessScanResult scan_res;
        int suspicious_raw = 0;
        int detection_enabled = 0;
        memset(&m, 0, sizeof(m));
        memset(&scan_res, 0, sizeof(scan_res));
        collect_metrics(&m);

        pthread_mutex_lock(&g_state.lock);
        detection_enabled = g_state.scan_enabled;
        pthread_mutex_unlock(&g_state.lock);

        if (detection_enabled && kcall_scan_processes(&scan_res) == 0) {
            unsigned int lim = scan_res.count;
            if (lim > SYS_SCAN_MAX) {
                lim = SYS_SCAN_MAX;
            }
            for (unsigned int i = 0; i < lim; i++) {
                if (scan_res.entries[i].rss_kb > (512ULL * 1024ULL)) {
                    suspicious_raw++;
                }
            }
        }

        pthread_mutex_lock(&g_state.lock);
        g_state.metrics = m;
        pthread_mutex_unlock(&g_state.lock);

        unsigned long mem_total = m.memoria_usada + m.memoria_libre + m.memoria_cache;
        double used_pct = 0.0;
        if (mem_total > 0) {
            used_pct = ((double)m.memoria_usada * 100.0) / (double)mem_total;
        }

        unsigned long major_delta = 0;
        if (prev_major > 0 && m.fallos_mayores >= prev_major) {
            major_delta = m.fallos_mayores - prev_major;
        }
        prev_major = m.fallos_mayores;

        if (detection_enabled) {
            if (used_pct > 85.0) {
                push_alert("memoria", "MEDIUM", "Alto consumo de memoria detectado");
            }
            if (major_delta > 1500) {
                push_alert("proceso", "HIGH", "Pico de fallos mayores detectado");
            }
            if (m.top_count > 0 && m.top[0].porcentaje > 25.0) {
                push_alert("proceso", "MEDIUM", "Proceso con consumo de memoria elevado");
            }
            if (suspicious_raw > 0) {
                push_alert("proceso", "MEDIUM", "Proceso sospechoso activo detectado por escaneo");
            }

            if (used_pct > 90.0 && major_delta > 1500 && suspicious_raw > 0) {
                push_alert("proceso", "HIGH", "Multiples alertas criticas simultaneas detectadas");
                try_simulate_panic("[SECURITY] Simulated kernel panic triggered: simultaneous critical conditions");
            }

            if (used_pct > 92.0 || major_delta > 2500) {
                high_streak++;
            } else {
                high_streak = 0;
            }

            if (high_streak >= 3) {
                push_alert("proceso", "HIGH", "Condicion critica persistente de monitoreo");
                try_simulate_panic("[SECURITY] Simulated kernel panic triggered: persistent anomaly");
                high_streak = 0;
            }
        } else {
            high_streak = 0;
        }

        for (int i = 0; i < g_monitor_interval && g_running; i++) {
            sleep(1);
        }
    }

    return NULL;
}

static int extract_json_field(const char *src, const char *key, char *out, size_t out_sz) {
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\"", key);

    const char *p = strstr(src, pat);
    if (!p) {
        return 0;
    }

    p = strchr(p, ':');
    if (!p) {
        return 0;
    }
    p++;

    while (*p == ' ' || *p == '\t') {
        p++;
    }

    if (*p != '"') {
        return 0;
    }
    p++;

    const char *q = strchr(p, '"');
    if (!q) {
        return 0;
    }

    size_t n = (size_t)(q - p);
    if (n >= out_sz) {
        n = out_sz - 1;
    }

    memcpy(out, p, n);
    out[n] = '\0';
    return 1;
}

static int extract_first_json_key(const char *src, char *out, size_t out_sz) {
    const char *p = strchr(src, '"');
    if (!p) {
        return 0;
    }
    p++;

    const char *q = strchr(p, '"');
    if (!q) {
        return 0;
    }

    const char *colon = q + 1;
    while (*colon == ' ' || *colon == '\t') {
        colon++;
    }
    if (*colon != ':') {
        return 0;
    }

    size_t n = (size_t)(q - p);
    if (n >= out_sz) {
        n = out_sz - 1;
    }
    memcpy(out, p, n);
    out[n] = '\0';
    return 1;
}

static int is_blacklist_field_key(const char *key) {
    return strcmp(key, "hash") == 0 ||
           strcmp(key, "nombre") == 0 ||
           strcmp(key, "severidad") == 0 ||
           strcmp(key, "descripcion") == 0;
}

static void uppercase_ascii(char *s) {
    for (size_t i = 0; s[i]; i++) {
        if (s[i] >= 'a' && s[i] <= 'z') {
            s[i] = (char)(s[i] - 'a' + 'A');
        }
    }
}

static int prompt_looks_like_user(const char *msg) {
    if (!msg) {
        return 0;
    }

    char lower[256];
    size_t i = 0;
    for (; msg[i] && i + 1 < sizeof(lower); i++) {
        char c = msg[i];
        if (c >= 'A' && c <= 'Z') {
            c = (char)(c - 'A' + 'a');
        }
        lower[i] = c;
    }
    lower[i] = '\0';

    return strstr(lower, "user") != NULL ||
           strstr(lower, "login") != NULL ||
           strstr(lower, "usuario") != NULL ||
           strstr(lower, "nombre") != NULL;
}

static int signature_hash_exists_nolock(const char *hash) {
    for (int i = 0; i < g_state.signature_count; i++) {
        if (strcmp(g_state.signatures[i].hash, hash) == 0) {
            return 1;
        }
    }
    return 0;
}

static void commit_signature_nolock(Signature *tmp, const char *fallback_name) {
    if (!tmp || tmp->hash[0] == '\0') {
        return;
    }
    if (signature_hash_exists_nolock(tmp->hash)) {
        memset(tmp, 0, sizeof(*tmp));
        return;
    }
    if (tmp->nombre[0] == '\0' && fallback_name && fallback_name[0]) {
        snprintf(tmp->nombre, sizeof(tmp->nombre), "%s", fallback_name);
    }
    if (tmp->nombre[0] == '\0') {
        snprintf(tmp->nombre, sizeof(tmp->nombre), "Unknown.Signature");
    }
    if (tmp->severidad[0] == '\0') {
        snprintf(tmp->severidad, sizeof(tmp->severidad), "HIGH");
    }
    uppercase_ascii(tmp->severidad);
    if (tmp->descripcion[0] == '\0') {
        snprintf(tmp->descripcion, sizeof(tmp->descripcion), "Firma detectada por hash");
    }

    if (g_state.signature_count < MAX_SIGNATURES) {
        g_state.signatures[g_state.signature_count++] = *tmp;
    }
    memset(tmp, 0, sizeof(*tmp));
}

static int load_blacklist(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        return -1;
    }

    pthread_mutex_lock(&g_state.lock);
    g_state.signature_count = 0;

    char line[1024];
    Signature tmp;
    char current_name[80];
    int in_entry = 0;

    memset(&tmp, 0, sizeof(tmp));
    memset(current_name, 0, sizeof(current_name));

    while (fgets(line, sizeof(line), f)) {
        trim_newline(line);

        char key[128] = {0};
        if (extract_first_json_key(line, key, sizeof(key)) && !is_blacklist_field_key(key) && strstr(line, "{")) {
            if (in_entry) {
                commit_signature_nolock(&tmp, current_name);
            }
            snprintf(current_name, sizeof(current_name), "%.79s", key);
            snprintf(tmp.nombre, sizeof(tmp.nombre), "%.79s", key);
            in_entry = 1;
        }

        char value[256];
        if (extract_json_field(line, "hash", value, sizeof(value))) {
            snprintf(tmp.hash, sizeof(tmp.hash), "%.64s", value);
            in_entry = 1;
        }
        if (extract_json_field(line, "nombre", value, sizeof(value))) {
            snprintf(tmp.nombre, sizeof(tmp.nombre), "%.79s", value);
            in_entry = 1;
        }
        if (extract_json_field(line, "severidad", value, sizeof(value))) {
            snprintf(tmp.severidad, sizeof(tmp.severidad), "%.7s", value);
            in_entry = 1;
        }
        if (extract_json_field(line, "descripcion", value, sizeof(value))) {
            snprintf(tmp.descripcion, sizeof(tmp.descripcion), "%.179s", value);
            in_entry = 1;
        }

        if (in_entry && strchr(line, '}')) {
            commit_signature_nolock(&tmp, current_name);
            current_name[0] = '\0';
            in_entry = 0;
        }

        if (g_state.signature_count >= MAX_SIGNATURES) {
            break;
        }
    }

    if (in_entry) {
        commit_signature_nolock(&tmp, current_name);
    }

    int loaded = g_state.signature_count;
    pthread_mutex_unlock(&g_state.lock);
    fclose(f);
    return loaded > 0 ? 0 : -1;
}

static int compute_sha256sum(const char *path, char out[65]) {
    char cmd[1200];
    snprintf(cmd, sizeof(cmd), "sha256sum \"%s\" 2>/dev/null", path);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        return -1;
    }

    char line[256];
    if (!fgets(line, sizeof(line), fp)) {
        pclose(fp);
        return -1;
    }
    pclose(fp);

    if (strlen(line) < 64) {
        return -1;
    }

    memcpy(out, line, 64);
    out[64] = '\0';
    return 0;
}

static int match_signature_by_hash(const char *hash, Signature *out) {
    int found = 0;

    pthread_mutex_lock(&g_state.lock);
    for (int i = 0; i < g_state.signature_count; i++) {
        if (strcmp(g_state.signatures[i].hash, hash) == 0) {
            if (out) {
                *out = g_state.signatures[i];
            }
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_state.lock);

    return found;
}

static int find_file_record(const char *path) {
    for (int i = 0; i < g_state.file_count; i++) {
        if (strcmp(g_state.files[i].path, path) == 0) {
            return i;
        }
    }
    return -1;
}

static int find_restored_path_nolock(const char *path) {
    for (int i = 0; i < g_state.restored_count; i++) {
        if (strcmp(g_state.restored_paths[i], path) == 0) {
            return i;
        }
    }
    return -1;
}

static int is_restored_path(const char *path) {
    int found = 0;
    pthread_mutex_lock(&g_state.lock);
    found = (find_restored_path_nolock(path) >= 0);
    pthread_mutex_unlock(&g_state.lock);
    return found;
}

static void mark_restored_path(const char *path) {
    pthread_mutex_lock(&g_state.lock);

    if (find_restored_path_nolock(path) >= 0) {
        pthread_mutex_unlock(&g_state.lock);
        return;
    }

    if (g_state.restored_count < MAX_FILES) {
        snprintf(g_state.restored_paths[g_state.restored_count], sizeof(g_state.restored_paths[g_state.restored_count]), "%s", path);
        g_state.restored_count++;
    } else {
        memmove(&g_state.restored_paths[0], &g_state.restored_paths[1], sizeof(g_state.restored_paths[0]) * (MAX_FILES - 1));
        snprintf(g_state.restored_paths[MAX_FILES - 1], sizeof(g_state.restored_paths[MAX_FILES - 1]), "%s", path);
    }

    pthread_mutex_unlock(&g_state.lock);
}

static void unmark_restored_path(const char *path) {
    pthread_mutex_lock(&g_state.lock);

    int idx = find_restored_path_nolock(path);
    if (idx >= 0) {
        if (idx < g_state.restored_count - 1) {
            memmove(&g_state.restored_paths[idx], &g_state.restored_paths[idx + 1], sizeof(g_state.restored_paths[0]) * (size_t)(g_state.restored_count - idx - 1));
        }
        g_state.restored_count--;
    }

    pthread_mutex_unlock(&g_state.lock);
}

static void update_file_record(const char *path, const char *hash, long mtime, const char *estado) {
    pthread_mutex_lock(&g_state.lock);

    int idx = find_file_record(path);
    if (idx < 0) {
        if (g_state.file_count < MAX_FILES) {
            idx = g_state.file_count++;
        } else {
            idx = MAX_FILES - 1;
        }
    }

    FileRecord *r = &g_state.files[idx];
    snprintf(r->path, sizeof(r->path), "%s", path);
    snprintf(r->hash, sizeof(r->hash), "%s", hash);
    r->mtime = mtime;
    snprintf(r->estado, sizeof(r->estado), "%s", estado);
    if (mtime > 0) {
        epoch_string((unsigned long long)mtime, r->timestamp, sizeof(r->timestamp));
    } else {
        now_string(r->timestamp, sizeof(r->timestamp));
    }

    pthread_mutex_unlock(&g_state.lock);
}

static void sync_quarantine_state(void) {
    SysQuarantineList list;
    memset(&list, 0, sizeof(list));

    if (kcall_get_quarantine_list(&list) != 0) {
        return;
    }

    pthread_mutex_lock(&g_state.lock);
    for (unsigned int i = 0; i < list.count && i < SYS_QUARANTINE_MAX; i++) {
        int idx = find_file_record(list.entries[i].path);
        if (idx >= 0) {
            snprintf(g_state.files[idx].estado, sizeof(g_state.files[idx].estado), "%s", "cuarentena");
        }
    }
    pthread_mutex_unlock(&g_state.lock);
}

static void scan_once(void) {
    char cmd[1200];
    snprintf(cmd, sizeof(cmd), "find \"%s\" -type f 2>/dev/null", g_watch_dir);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        push_alert("archivo", "LOW", "No fue posible ejecutar escaneo de archivos");
        return;
    }

    char path[MAX_PATH];
    while (fgets(path, sizeof(path), fp)) {
        trim_newline(path);
        if (path[0] == '\0') {
            continue;
        }

        char hash[65];
        long mtime = 0;
        int analysis_ok = 0;
        SysFileAnalysisInfo finfo;
        memset(&finfo, 0, sizeof(finfo));

        if (kcall_file_analize(path, &finfo) == 0) {
            snprintf(hash, sizeof(hash), "%s", finfo.sha256);
            mtime = (long)finfo.mtime_sec;
            analysis_ok = 1;
        } else {
            struct stat st;
            if (stat(path, &st) != 0) {
                continue;
            }
            if (compute_sha256sum(path, hash) != 0) {
                continue;
            }
            mtime = st.st_mtime;
            analysis_ok = 1;
        }

        if (!analysis_ok) {
            continue;
        }

        int is_new = 0;
        int is_modified = 0;
        int was_suspicious = 0;
        int was_quarantined = 0;
        int idx = -1;

        pthread_mutex_lock(&g_state.lock);
        idx = find_file_record(path);
        if (idx < 0) {
            is_new = 1;
        } else {
            if (strcmp(g_state.files[idx].estado, "sospechoso") == 0 ||
                strcmp(g_state.files[idx].estado, "cuarentena") == 0) {
                was_suspicious = 1;
            }
            if (strcmp(g_state.files[idx].estado, "cuarentena") == 0) {
                was_quarantined = 1;
            }
            if (strcmp(g_state.files[idx].hash, hash) != 0 || g_state.files[idx].mtime != mtime) {
                is_modified = 1;
            }
        }
        pthread_mutex_unlock(&g_state.lock);

        if (is_modified) {
            /* If content changed after a manual restore, resume normal evaluation. */
            unmark_restored_path(path);
        }

        if (is_new) {
            push_alert("archivo", "LOW", "Archivo nuevo detectado durante escaneo");
            update_file_record(path, hash, mtime, "limpio");
        } else if (is_modified) {
            push_alert("archivo", "MEDIUM", "Archivo modificado detectado durante escaneo");
            update_file_record(path, hash, mtime, "modificado");
        }

        Signature sig;
        if (match_signature_by_hash(hash, &sig)) {
            const char *sev = sig.severidad[0] ? sig.severidad : "HIGH";
            int restored_manual = is_restored_path(path);
            if (strcmp(sev, "HIGH") == 0) {
                if (restored_manual) {
                    /* Tutor guidance: manual restore can remain out of quarantine. */
                    update_file_record(path, hash, mtime, "sospechoso");
                } else {
                    int quarantine_ok = (kcall_quarantine_file(path) == 0);
                    update_file_record(path, hash, mtime, quarantine_ok ? "cuarentena" : "sospechoso");
                }
            } else {
                update_file_record(path, hash, mtime, "sospechoso");
            }

            push_alert("archivo", sev, "Coincidencia con firma maliciosa");
            push_threat(sig.nombre, path, sig.severidad, sig.descripcion);
            if (strcmp(sev, "HIGH") == 0 && !restored_manual) {
                char msg[300];
                snprintf(msg, sizeof(msg), "[SECURITY] Simulated kernel panic triggered: %s", sig.nombre);
                try_simulate_panic(msg);
            }
        } else if (is_new) {
            update_file_record(path, hash, mtime, "limpio");
        } else if (is_modified) {
            if (was_quarantined || was_suspicious) {
                update_file_record(path, hash, mtime, "sospechoso");
            } else {
                update_file_record(path, hash, mtime, "modificado");
            }
        }
    }

    pclose(fp);
    sync_quarantine_state();
}

static void *scan_thread(void *arg) {
    (void)arg;

    while (g_running) {
        int enabled = 0;
        pthread_mutex_lock(&g_state.lock);
        enabled = g_state.scan_enabled;
        pthread_mutex_unlock(&g_state.lock);

        if (enabled) {
            scan_once();
        }

        for (int i = 0; i < g_scan_interval && g_running; i++) {
            sleep(1);
        }
    }

    return NULL;
}

typedef struct {
    const char *user;
    const char *pass;
} PamCredentials;

static int pam_conv_fn(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {
    PamCredentials *creds = (PamCredentials *)appdata_ptr;
    if (num_msg <= 0) {
        return PAM_CONV_ERR;
    }

    struct pam_response *responses = calloc((size_t)num_msg, sizeof(struct pam_response));
    if (!responses) {
        return PAM_CONV_ERR;
    }

    for (int i = 0; i < num_msg; i++) {
        auth_debug_log("pam_conv msg[%d] style=%d text=%s", i, msg[i] ? msg[i]->msg_style : -1, (msg[i] && msg[i]->msg) ? msg[i]->msg : "(null)");
        switch (msg[i]->msg_style) {
            case PAM_PROMPT_ECHO_OFF:
                auth_debug_log("pam_conv msg[%d] -> using password (echo_off)", i);
                responses[i].resp = strdup(creds && creds->pass ? creds->pass : "");
                responses[i].resp_retcode = 0;
                if (!responses[i].resp) {
                    for (int j = 0; j <= i; j++) {
                        free(responses[j].resp);
                    }
                    free(responses);
                    return PAM_CONV_ERR;
                }
                break;
            case PAM_PROMPT_ECHO_ON:
                if (prompt_looks_like_user(msg[i] ? msg[i]->msg : NULL)) {
                    auth_debug_log("pam_conv msg[%d] -> using username (echo_on)", i);
                    responses[i].resp = strdup(creds && creds->user ? creds->user : "");
                } else {
                    auth_debug_log("pam_conv msg[%d] -> using password (echo_on)", i);
                    responses[i].resp = strdup(creds && creds->pass ? creds->pass : "");
                }
                responses[i].resp_retcode = 0;
                if (!responses[i].resp) {
                    for (int j = 0; j <= i; j++) {
                        free(responses[j].resp);
                    }
                    free(responses);
                    return PAM_CONV_ERR;
                }
                break;
            case PAM_ERROR_MSG:
            case PAM_TEXT_INFO:
                auth_debug_log("pam_conv msg[%d] -> informational", i);
                responses[i].resp = NULL;
                responses[i].resp_retcode = 0;
                break;
            default:
                for (int j = 0; j <= i; j++) {
                    free(responses[j].resp);
                }
                free(responses);
                return PAM_CONV_ERR;
        }
    }

    *resp = responses;
    return PAM_SUCCESS;
}

static int authenticate_with_pam(const char *user, const char *pass) {
    PamCredentials creds = {user, pass};
    struct pam_conv conv = {pam_conv_fn, (void *)&creds};
    pam_handle_t *pamh = NULL;
    int ret = pam_start("security_daemon", user, &conv, &pamh);
    if (ret != PAM_SUCCESS || !pamh) {
        auth_debug_log("pam_start fail user=%s ret=%d", user ? user : "(null)", ret);
        if (pamh) {
            pam_end(pamh, ret);
        }
        return 0;
    }

    (void)pam_set_item(pamh, PAM_TTY, "pts/0");
    (void)pam_set_item(pamh, PAM_RHOST, "127.0.0.1");

    ret = pam_authenticate(pamh, 0);
    auth_debug_log("pam_authenticate user=%s ret=%d (%s)", user ? user : "(null)", ret, pam_strerror(pamh, ret));
    if (ret == PAM_SUCCESS) {
        ret = pam_acct_mgmt(pamh, 0);
        auth_debug_log("pam_acct_mgmt user=%s ret=%d (%s)", user ? user : "(null)", ret, pam_strerror(pamh, ret));
        if (ret == PAM_NEW_AUTHTOK_REQD) {
            ret = PAM_SUCCESS;
        }
    }

    pam_end(pamh, ret);
    return ret == PAM_SUCCESS;
}

static int user_in_group(const char *username, const char *group_name) {
    struct group *gr = getgrnam(group_name);
    if (!gr) {
        return 0;
    }

    struct passwd *pw = getpwnam(username);
    if (pw && pw->pw_gid == gr->gr_gid) {
        return 1;
    }

    for (char **m = gr->gr_mem; m && *m; m++) {
        if (strcmp(*m, username) == 0) {
            return 1;
        }
    }

    return 0;
}

static int resolve_role(const char *username, char *role_out, size_t role_out_sz) {
    int is_admin = user_in_group(username, "admin_user");
    int is_common = user_in_group(username, "common_user");

    if (is_admin) {
        snprintf(role_out, role_out_sz, "admin");
        return 1;
    }
    if (is_common) {
        snprintf(role_out, role_out_sz, "common");
        return 1;
    }
    return 0;
}

static int is_safe_username(const char *username) {
    size_t len = username ? strlen(username) : 0;
    if (len < 3 || len > 32) {
        return 0;
    }

    char first = username[0];
    if (!((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z'))) {
        return 0;
    }

    for (size_t i = 0; i < len; i++) {
        char c = username[i];
        if ((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c == '_' || c == '-') {
            continue;
        }
        return 0;
    }

    return 1;
}

static int is_safe_password(const char *password) {
    size_t len = password ? strlen(password) : 0;
    if (len < 8 || len > 64) {
        return 0;
    }

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)password[i];
        if (c < 33 || c > 126 || c == ':') {
            return 0;
        }
    }

    return 1;
}

static int run_command_capture(char *const argv[],
                               const char *stdin_data,
                               char *errbuf,
                               size_t errbuf_sz) {
    int err_pipe[2] = {-1, -1};
    int in_pipe[2] = {-1, -1};

    if (pipe(err_pipe) != 0) {
        snprintf(errbuf, errbuf_sz, "No se pudo abrir pipe de error");
        return -1;
    }

    if (stdin_data && pipe(in_pipe) != 0) {
        close(err_pipe[0]);
        close(err_pipe[1]);
        snprintf(errbuf, errbuf_sz, "No se pudo abrir pipe de entrada");
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(err_pipe[0]);
        close(err_pipe[1]);
        if (stdin_data) {
            close(in_pipe[0]);
            close(in_pipe[1]);
        }
        snprintf(errbuf, errbuf_sz, "No se pudo crear proceso hijo");
        return -1;
    }

    if (pid == 0) {
        dup2(err_pipe[1], STDERR_FILENO);
        dup2(err_pipe[1], STDOUT_FILENO);
        close(err_pipe[0]);
        close(err_pipe[1]);

        if (stdin_data) {
            close(in_pipe[1]);
            dup2(in_pipe[0], STDIN_FILENO);
            close(in_pipe[0]);
        }

        execvp(argv[0], argv);
        _exit(127);
    }

    close(err_pipe[1]);

    if (stdin_data) {
        close(in_pipe[0]);
        size_t total = strlen(stdin_data);
        size_t off = 0;
        while (off < total) {
            ssize_t written = write(in_pipe[1], stdin_data + off, total - off);
            if (written < 0) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }
            off += (size_t)written;
        }
        close(in_pipe[1]);
    }

    if (errbuf_sz > 0) {
        errbuf[0] = '\0';
    }

    size_t used = 0;
    while (errbuf_sz > 0 && used + 1 < errbuf_sz) {
        ssize_t nr = read(err_pipe[0], errbuf + used, errbuf_sz - used - 1);
        if (nr < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (nr == 0) {
            break;
        }
        used += (size_t)nr;
    }
    close(err_pipe[0]);

    if (errbuf_sz > 0) {
        errbuf[used] = '\0';
        trim_newline(errbuf);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        snprintf(errbuf, errbuf_sz, "No se pudo esperar proceso hijo");
        return -1;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return 0;
    }

    if (errbuf_sz > 0 && errbuf[0] == '\0') {
        if (WIFEXITED(status)) {
            snprintf(errbuf, errbuf_sz, "Comando fallo con codigo %d", WEXITSTATUS(status));
        } else {
            snprintf(errbuf, errbuf_sz, "Comando terminado de forma inesperada");
        }
    }

    return -1;
}

static int run_privileged_command(char *const base_argv[],
                                  const char *stdin_data,
                                  char *errbuf,
                                  size_t errbuf_sz) {
    char *argv[16];
    int idx = 0;

    if (geteuid() != 0) {
        argv[idx++] = "sudo";
        argv[idx++] = "-n";
    }

    for (int i = 0; base_argv[i] && idx < (int)(sizeof(argv) / sizeof(argv[0])) - 1; i++) {
        argv[idx++] = base_argv[i];
    }
    argv[idx] = NULL;

    return run_command_capture(argv, stdin_data, errbuf, errbuf_sz);
}

static int ensure_system_group_exists(const char *group_name, char *errbuf, size_t errbuf_sz) {
    if (getgrnam(group_name)) {
        return 0;
    }

    char *argv[] = {"groupadd", (char *)group_name, NULL};
    return run_privileged_command(argv, NULL, errbuf, errbuf_sz);
}

static int rollback_created_user(const char *username) {
    char errbuf[256];
    char *argv[] = {"userdel", "-r", (char *)username, NULL};
    return run_privileged_command(argv, NULL, errbuf, sizeof(errbuf));
}

static int create_system_user_account(const char *username,
                                      const char *password,
                                      const char *role_name,
                                      char *errbuf,
                                      size_t errbuf_sz) {
    const char *group_name = NULL;
    if (strcmp(role_name, "admin") == 0) {
        group_name = "admin_user";
    } else if (strcmp(role_name, "common") == 0) {
        group_name = "common_user";
    } else {
        snprintf(errbuf, errbuf_sz, "Rol invalido");
        return -1;
    }

    if (!is_safe_username(username)) {
        snprintf(errbuf, errbuf_sz, "El usuario debe tener 3-32 caracteres y solo usar letras, numeros, guion o guion bajo");
        return -1;
    }

    if (!is_safe_password(password)) {
        snprintf(errbuf, errbuf_sz, "La contrasena debe tener 8-64 caracteres ASCII sin espacios ni ':'");
        return -1;
    }

    if (getpwnam(username)) {
        snprintf(errbuf, errbuf_sz, "El usuario ya existe en el sistema");
        return -1;
    }

    if (ensure_system_group_exists(group_name, errbuf, errbuf_sz) != 0) {
        return -1;
    }

    char *useradd_argv[] = {
        "useradd",
        "-m",
        "-s",
        "/bin/bash",
        "-G",
        (char *)group_name,
        (char *)username,
        NULL
    };

    if (run_privileged_command(useradd_argv, NULL, errbuf, errbuf_sz) != 0) {
        return -1;
    }

    char creds[160];
    snprintf(creds, sizeof(creds), "%s:%s\n", username, password);
    char *passwd_argv[] = {"chpasswd", NULL};
    if (run_privileged_command(passwd_argv, creds, errbuf, errbuf_sz) != 0) {
        (void)rollback_created_user(username);
        return -1;
    }

    return 0;
}

static int is_protected_system_username(const char *target, const char *current_user) {
    if (!target || !*target) {
        return 1;
    }

    return strcmp(target, "root") == 0 ||
           strcmp(target, "daniel") == 0 ||
           (current_user && strcmp(target, current_user) == 0);
}

static int delete_system_user_account(const char *username,
                                      const char *current_user,
                                      char *deleted_role_out,
                                      size_t deleted_role_out_sz,
                                      char *errbuf,
                                      size_t errbuf_sz) {
    if (!is_safe_username(username)) {
        snprintf(errbuf, errbuf_sz, "Nombre de usuario invalido");
        return -1;
    }

    if (is_protected_system_username(username, current_user)) {
        snprintf(errbuf, errbuf_sz, "Ese usuario esta protegido y no se puede eliminar");
        return -1;
    }

    struct passwd *pw = getpwnam(username);
    if (!pw) {
        snprintf(errbuf, errbuf_sz, "El usuario no existe");
        return -1;
    }

    int is_admin = user_in_group(username, "admin_user");
    int is_common = user_in_group(username, "common_user");
    if (!is_admin && !is_common) {
        snprintf(errbuf, errbuf_sz, "Solo se pueden eliminar usuarios administrados por el sistema");
        return -1;
    }

    if (deleted_role_out && deleted_role_out_sz > 0) {
        snprintf(deleted_role_out, deleted_role_out_sz, "%s", is_admin ? "admin" : "common");
    }

    char *argv[] = {"userdel", "-r", (char *)username, NULL};
    return run_privileged_command(argv, NULL, errbuf, errbuf_sz);
}

static void random_token(char out[65]) {
    int fd = open("/dev/urandom", O_RDONLY);
    unsigned char buf[32];
    if (fd >= 0) {
        ssize_t n = read(fd, buf, sizeof(buf));
        close(fd);
        if (n == (ssize_t)sizeof(buf)) {
            for (int i = 0; i < 32; i++) {
                snprintf(out + (i * 2), 3, "%02x", buf[i]);
            }
            out[64] = '\0';
            return;
        }
    }

    srand((unsigned)time(NULL));
    for (int i = 0; i < 64; i++) {
        const char hex[] = "0123456789abcdef";
        out[i] = hex[rand() % 16];
    }
    out[64] = '\0';
}

static int create_session(const char *username, const char *role, char token_out[65]) {
    pthread_mutex_lock(&g_state.lock);

    int idx = -1;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_state.sessions[i].active) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        idx = 0;
    }

    Session *s = &g_state.sessions[idx];
    random_token(s->token);
    snprintf(s->username, sizeof(s->username), "%s", username);
    snprintf(s->role, sizeof(s->role), "%s", role);
    s->created = time(NULL);
    s->active = 1;

    snprintf(token_out, 65, "%s", s->token);

    pthread_mutex_unlock(&g_state.lock);
    return 1;
}

static int get_session_from_token(const char *token, char *user_out, size_t user_sz, char *role_out, size_t role_sz) {
    if (!token || !*token) {
        return 0;
    }

    int ok = 0;
    pthread_mutex_lock(&g_state.lock);
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (g_state.sessions[i].active && strcmp(g_state.sessions[i].token, token) == 0) {
            snprintf(user_out, user_sz, "%s", g_state.sessions[i].username);
            snprintf(role_out, role_sz, "%s", g_state.sessions[i].role);
            ok = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_state.lock);

    return ok;
}

static int extract_bearer_token(const char *req, char *token_out, size_t token_sz) {
    const char *p = strstr(req, "Authorization: Bearer ");
    if (!p) {
        return 0;
    }

    p += strlen("Authorization: Bearer ");
    const char *end = strstr(p, "\r\n");
    if (!end) {
        return 0;
    }

    size_t n = (size_t)(end - p);
    if (n >= token_sz) {
        n = token_sz - 1;
    }

    memcpy(token_out, p, n);
    token_out[n] = '\0';
    return 1;
}

static void send_response(int fd, int status_code, const char *content_type, const char *body) {
    static const char *status_texts[] = {
        "", "", "", "", "", "", "", "", "", "", "",
    };
    (void)status_texts;

    const char *reason = "OK";
    if (status_code == 400) reason = "Bad Request";
    else if (status_code == 401) reason = "Unauthorized";
    else if (status_code == 403) reason = "Forbidden";
    else if (status_code == 404) reason = "Not Found";
    else if (status_code == 405) reason = "Method Not Allowed";
    else if (status_code == 500) reason = "Internal Server Error";

    char header[512];
    int body_len = body ? (int)strlen(body) : 0;
    int h = snprintf(
        header,
        sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n",
        status_code,
        reason,
        content_type,
        body_len
    );

    send(fd, header, (size_t)h, 0);
    if (body_len > 0) {
        send(fd, body, (size_t)body_len, 0);
    }
}

static void send_json_msg(int fd, int status_code, const char *msg) {
    char body[512];
    char escaped[320];
    json_escape(msg, escaped, sizeof(escaped));
    snprintf(body, sizeof(body), "{\"ok\":false,\"message\":\"%s\"}", escaped);
    send_response(fd, status_code, "application/json", body);
}

static int parse_pid_from_path(const char *path) {
    const char *q = strstr(path, "pid=");
    if (!q) {
        return -1;
    }
    q += 4;
    if (!is_number_str(q)) {
        return -1;
    }
    return atoi(q);
}

static int build_metrics_json(char *out, size_t out_sz) {
    Metrics m;
    pthread_mutex_lock(&g_state.lock);
    m = g_state.metrics;
    pthread_mutex_unlock(&g_state.lock);

    int n = snprintf(
        out,
        out_sz,
        "{\"memoria_usada\":%lu,\"memoria_libre\":%lu,\"memoria_cache\":%lu,\"swap_usada\":%lu,"
        "\"fallos_menores\":%lu,\"fallos_mayores\":%lu,\"paginas_activas\":%lu,\"paginas_inactivas\":%lu,\"procesos_top\":[",
        m.memoria_usada,
        m.memoria_libre,
        m.memoria_cache,
        m.swap_usada,
        m.fallos_menores,
        m.fallos_mayores,
        m.paginas_activas,
        m.paginas_inactivas
    );

    for (int i = 0; i < m.top_count && n > 0 && (size_t)n < out_sz; i++) {
        char name[128];
        json_escape(m.top[i].nombre, name, sizeof(name));
        n += snprintf(
            out + n,
            out_sz - (size_t)n,
            "%s{\"nombre\":\"%s\",\"pid\":%d,\"porcentaje\":%.2f}",
            (i == 0 ? "" : ","),
            name,
            m.top[i].pid,
            m.top[i].porcentaje
        );
    }

    if (n > 0 && (size_t)n < out_sz) {
        n += snprintf(out + n, out_sz - (size_t)n, "]}");
    }

    return n;
}

static int build_alerts_json(char *out, size_t out_sz) {
    Alert copy[MAX_ALERTS];
    int count = 0;

    pthread_mutex_lock(&g_state.lock);
    count = g_state.alert_count;
    if (count > MAX_ALERTS) {
        count = MAX_ALERTS;
    }
    memcpy(copy, g_state.alerts, sizeof(Alert) * (size_t)count);
    pthread_mutex_unlock(&g_state.lock);

    int n = snprintf(out, out_sz, "{");
    n += snprintf(out + n, out_sz - (size_t)n, "\"items\":[");

    for (int i = count - 1; i >= 0 && n > 0 && (size_t)n < out_sz; i--) {
        char tipo[64], sev[32], desc[400], ts[64];
        json_escape(copy[i].tipo, tipo, sizeof(tipo));
        json_escape(copy[i].severidad, sev, sizeof(sev));
        json_escape(copy[i].descripcion, desc, sizeof(desc));
        json_escape(copy[i].timestamp, ts, sizeof(ts));

        n += snprintf(
            out + n,
            out_sz - (size_t)n,
            "%s{\"tipo\":\"%s\",\"severidad\":\"%s\",\"descripcion\":\"%s\",\"timestamp\":\"%s\"}",
            (i == count - 1 ? "" : ","),
            tipo,
            sev,
            desc,
            ts
        );
    }

    if (n > 0 && (size_t)n < out_sz) {
        n += snprintf(out + n, out_sz - (size_t)n, "]}");
    }
    return n;
}

static int build_files_json(char *out, size_t out_sz) {
    FileRecord copy[MAX_FILES];
    int count = 0;

    pthread_mutex_lock(&g_state.lock);
    count = g_state.file_count;
    if (count > MAX_FILES) {
        count = MAX_FILES;
    }
    memcpy(copy, g_state.files, sizeof(FileRecord) * (size_t)count);
    pthread_mutex_unlock(&g_state.lock);

    int n = snprintf(out, out_sz, "{\"items\":[");

    for (int i = count - 1; i >= 0 && n > 0 && (size_t)n < out_sz; i--) {
        char path[1300], estado[32], ts[64], hash[80];
        const char *estado_view = copy[i].estado;
        if (strcmp(estado_view, "nuevo") == 0) {
            estado_view = "limpio";
        }
        json_escape(copy[i].path, path, sizeof(path));
        json_escape(estado_view, estado, sizeof(estado));
        json_escape(copy[i].timestamp, ts, sizeof(ts));
        json_escape(copy[i].hash, hash, sizeof(hash));

        n += snprintf(
            out + n,
            out_sz - (size_t)n,
            "%s{\"path\":\"%s\",\"estado\":\"%s\",\"hash\":\"%s\",\"timestamp\":\"%s\"}",
            (i == count - 1 ? "" : ","),
            path,
            estado,
            hash,
            ts
        );
    }

    if (n > 0 && (size_t)n < out_sz) {
        n += snprintf(out + n, out_sz - (size_t)n, "]}");
    }
    return n;
}

static int build_threats_json(char *out, size_t out_sz) {
    ThreatEvent copy[MAX_THREATS];
    int count = 0;

    pthread_mutex_lock(&g_state.lock);
    count = g_state.threat_count;
    if (count > MAX_THREATS) {
        count = MAX_THREATS;
    }
    memcpy(copy, g_state.threats, sizeof(ThreatEvent) * (size_t)count);
    pthread_mutex_unlock(&g_state.lock);

    int n = snprintf(out, out_sz, "{\"items\":[");

    for (int i = count - 1; i >= 0 && n > 0 && (size_t)n < out_sz; i--) {
        char nombre[128], archivo[1300], sev[32], desc[300], ts[64];
        json_escape(copy[i].nombre, nombre, sizeof(nombre));
        json_escape(copy[i].archivo, archivo, sizeof(archivo));
        json_escape(copy[i].severidad, sev, sizeof(sev));
        json_escape(copy[i].descripcion, desc, sizeof(desc));
        json_escape(copy[i].timestamp, ts, sizeof(ts));

        n += snprintf(
            out + n,
            out_sz - (size_t)n,
            "%s{\"nombre\":\"%s\",\"archivo\":\"%s\",\"severidad\":\"%s\",\"descripcion\":\"%s\",\"timestamp\":\"%s\"}",
            (i == count - 1 ? "" : ","),
            nombre,
            archivo,
            sev,
            desc,
            ts
        );
    }

    if (n > 0 && (size_t)n < out_sz) {
        n += snprintf(out + n, out_sz - (size_t)n, "]}");
    }
    return n;
}

static int build_quarantine_json(char *out, size_t out_sz) {
    SysQuarantineList list;
    memset(&list, 0, sizeof(list));

    if (kcall_get_quarantine_list(&list) != 0) {
        return snprintf(out, out_sz, "{\"ok\":false,\"message\":\"No se pudo obtener cuarentena\"}");
    }

    unsigned int count = list.count;
    if (count > SYS_QUARANTINE_MAX) {
        count = SYS_QUARANTINE_MAX;
    }

    int n = snprintf(out, out_sz, "{\"ok\":true,\"items\":[");
    for (unsigned int i = 0; i < count && n > 0 && (size_t)n < out_sz; i++) {
        char path[512];
        char ts[64];
        json_escape(list.entries[i].path, path, sizeof(path));
        epoch_string(list.entries[i].quarantined_at_sec, ts, sizeof(ts));

        n += snprintf(
            out + n,
            out_sz - (size_t)n,
            "%s{\"path\":\"%s\",\"timestamp\":\"%s\"}",
            (i == 0 ? "" : ","),
            path,
            ts
        );
    }

    if (n > 0 && (size_t)n < out_sz) {
        n += snprintf(out + n, out_sz - (size_t)n, "]}");
    }
    return n;
}

static int build_me_json(const char *user, const char *role, char *out, size_t out_sz) {
    int enabled = 0;
    pthread_mutex_lock(&g_state.lock);
    enabled = g_state.scan_enabled;
    pthread_mutex_unlock(&g_state.lock);

    char u[128], r[32];
    json_escape(user, u, sizeof(u));
    json_escape(role, r, sizeof(r));

    return snprintf(
        out,
        out_sz,
        "{\"username\":\"%s\",\"role\":\"%s\",\"scan_enabled\":%s}",
        u,
        r,
        enabled ? "true" : "false"
    );
}

static int build_admin_users_json(const char *current_user, char *out, size_t out_sz) {
    struct passwd *pw = NULL;
    int n = snprintf(out, out_sz, "{\"ok\":true,\"items\":[");
    int first = 1;

    setpwent();
    while ((pw = getpwent()) != NULL && n > 0 && (size_t)n < out_sz) {
        const char *username = pw->pw_name;
        int is_admin = user_in_group(username, "admin_user");
        int is_common = user_in_group(username, "common_user");
        if (!is_admin && !is_common) {
            continue;
        }

        const char *role = is_admin ? "admin" : "common";
        int is_self = (current_user && strcmp(username, current_user) == 0);
        int is_protected = is_protected_system_username(username, current_user);
        const char *protected_reason = "";
        if (strcmp(username, "daniel") == 0) {
            protected_reason = "Usuario principal protegido";
        } else if (strcmp(username, "root") == 0) {
            protected_reason = "Cuenta root protegida";
        } else if (is_self) {
            protected_reason = "Sesion actual";
        }

        char username_esc[128], role_esc[32], reason_esc[160];
        json_escape(username, username_esc, sizeof(username_esc));
        json_escape(role, role_esc, sizeof(role_esc));
        json_escape(protected_reason, reason_esc, sizeof(reason_esc));

        n += snprintf(
            out + n,
            out_sz - (size_t)n,
            "%s{\"username\":\"%s\",\"role\":\"%s\",\"protected\":%s,\"self\":%s,\"protected_reason\":\"%s\"}",
            first ? "" : ",",
            username_esc,
            role_esc,
            is_protected ? "true" : "false",
            is_self ? "true" : "false",
            reason_esc
        );
        first = 0;
    }
    endpwent();

    if (n > 0 && (size_t)n < out_sz) {
        n += snprintf(out + n, out_sz - (size_t)n, "]}");
    }
    return n;
}

static int build_summary_report_json(const char *user, const char *role, char *out, size_t out_sz) {
    Metrics m;
    int alert_count = 0;
    int file_count = 0;
    int threat_count = 0;
    int suspicious_count = 0;
    int enabled = 0;
    ThreatEvent last_high;
    int has_high = 0;
    char generated_at[32];

    memset(&m, 0, sizeof(m));
    memset(&last_high, 0, sizeof(last_high));

    pthread_mutex_lock(&g_state.lock);
    m = g_state.metrics;
    alert_count = g_state.alert_count;
    if (alert_count > MAX_ALERTS) {
        alert_count = MAX_ALERTS;
    }

    file_count = g_state.file_count;
    if (file_count > MAX_FILES) {
        file_count = MAX_FILES;
    }

    for (int i = 0; i < file_count; i++) {
        if (strcmp(g_state.files[i].estado, "sospechoso") == 0 ||
            strcmp(g_state.files[i].estado, "cuarentena") == 0) {
            suspicious_count++;
        }
    }

    threat_count = g_state.threat_count;
    if (threat_count > MAX_THREATS) {
        threat_count = MAX_THREATS;
    }

    for (int i = threat_count - 1; i >= 0; i--) {
        if (strcmp(g_state.threats[i].severidad, "HIGH") == 0) {
            last_high = g_state.threats[i];
            has_high = 1;
            break;
        }
    }

    enabled = g_state.scan_enabled;
    pthread_mutex_unlock(&g_state.lock);

    now_string(generated_at, sizeof(generated_at));

    char u[128], r[32], gen[64];
    json_escape(user, u, sizeof(u));
    json_escape(role, r, sizeof(r));
    json_escape(generated_at, gen, sizeof(gen));

    if (has_high) {
        char name[128], file[1300], sev[32], desc[300], ts[64];
        json_escape(last_high.nombre, name, sizeof(name));
        json_escape(last_high.archivo, file, sizeof(file));
        json_escape(last_high.severidad, sev, sizeof(sev));
        json_escape(last_high.descripcion, desc, sizeof(desc));
        json_escape(last_high.timestamp, ts, sizeof(ts));

        return snprintf(
            out,
            out_sz,
            "{\"ok\":true,\"generated_at\":\"%s\",\"requested_by\":{\"username\":\"%s\",\"role\":\"%s\"},"
            "\"scan_enabled\":%s,\"summary\":{\"alerts\":%d,\"files\":%d,\"suspicious_files\":%d,\"threats\":%d},"
            "\"metrics\":{\"memoria_usada\":%lu,\"memoria_libre\":%lu,\"memoria_cache\":%lu,\"swap_usada\":%lu,"
            "\"fallos_menores\":%lu,\"fallos_mayores\":%lu},"
            "\"last_high_threat\":{\"nombre\":\"%s\",\"archivo\":\"%s\",\"severidad\":\"%s\",\"descripcion\":\"%s\",\"timestamp\":\"%s\"}}",
            gen,
            u,
            r,
            enabled ? "true" : "false",
            alert_count,
            file_count,
            suspicious_count,
            threat_count,
            m.memoria_usada,
            m.memoria_libre,
            m.memoria_cache,
            m.swap_usada,
            m.fallos_menores,
            m.fallos_mayores,
            name,
            file,
            sev,
            desc,
            ts
        );
    }

    return snprintf(
        out,
        out_sz,
        "{\"ok\":true,\"generated_at\":\"%s\",\"requested_by\":{\"username\":\"%s\",\"role\":\"%s\"},"
        "\"scan_enabled\":%s,\"summary\":{\"alerts\":%d,\"files\":%d,\"suspicious_files\":%d,\"threats\":%d},"
        "\"metrics\":{\"memoria_usada\":%lu,\"memoria_libre\":%lu,\"memoria_cache\":%lu,\"swap_usada\":%lu,"
        "\"fallos_menores\":%lu,\"fallos_mayores\":%lu},\"last_high_threat\":null}",
        gen,
        u,
        r,
        enabled ? "true" : "false",
        alert_count,
        file_count,
        suspicious_count,
        threat_count,
        m.memoria_usada,
        m.memoria_libre,
        m.memoria_cache,
        m.swap_usada,
        m.fallos_menores,
        m.fallos_mayores
    );
}

static int build_process_json(int pid, char *out, size_t out_sz) {
    SysProcessInfo pinfo;
    memset(&pinfo, 0, sizeof(pinfo));

    if (kcall_get_process_info(pid, &pinfo) == 0) {
        double cpu_s = (double)pinfo.exec_time_ns / 1000000000.0;
        char name_esc[128];
        json_escape(pinfo.comm, name_esc, sizeof(name_esc));
        return snprintf(
            out,
            out_sz,
            "{\"ok\":true,\"proceso\":\"%s\",\"pid\":%d,\"tiempo_cpu\":%.2f,\"memoria_rss_kb\":%llu}",
            name_esc,
            pinfo.pid,
            cpu_s,
            pinfo.mem_kb
        );
    }

    char comm_path[128], stat_path[128], statm_path[128];
    snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
    snprintf(statm_path, sizeof(statm_path), "/proc/%d/statm", pid);

    FILE *f_comm = fopen(comm_path, "r");
    if (!f_comm) {
        return snprintf(out, out_sz, "{\"ok\":false,\"message\":\"PID no encontrado\"}");
    }

    char name[64] = {0};
    if (!fgets(name, sizeof(name), f_comm)) {
        fclose(f_comm);
        return snprintf(out, out_sz, "{\"ok\":false,\"message\":\"No se pudo leer nombre del proceso\"}");
    }
    fclose(f_comm);
    trim_newline(name);

    FILE *f_stat = fopen(stat_path, "r");
    if (!f_stat) {
        return snprintf(out, out_sz, "{\"ok\":false,\"message\":\"No se pudo leer stat\"}");
    }

    char line[2048];
    if (!fgets(line, sizeof(line), f_stat)) {
        fclose(f_stat);
        return snprintf(out, out_sz, "{\"ok\":false,\"message\":\"No se pudo leer stat\"}");
    }
    fclose(f_stat);

    char *save = NULL;
    char *tok = strtok_r(line, " ", &save);
    int idx = 1;
    unsigned long utime = 0, stime = 0;
    while (tok) {
        if (idx == 14) utime = strtoul(tok, NULL, 10);
        if (idx == 15) stime = strtoul(tok, NULL, 10);
        idx++;
        tok = strtok_r(NULL, " ", &save);
    }

    FILE *f_statm = fopen(statm_path, "r");
    unsigned long rss_pages = 0;
    if (f_statm) {
        unsigned long size_pages = 0;
        if (fscanf(f_statm, "%lu %lu", &size_pages, &rss_pages) != 2) {
            rss_pages = 0;
        }
        fclose(f_statm);
    }

    double cpu_s = (double)(utime + stime) / (double)sysconf(_SC_CLK_TCK);
    unsigned long rss_kb = rss_pages * (unsigned long)(sysconf(_SC_PAGESIZE) / 1024);

    char name_esc[128];
    json_escape(name, name_esc, sizeof(name_esc));

    return snprintf(
        out,
        out_sz,
        "{\"ok\":true,\"proceso\":\"%s\",\"pid\":%d,\"tiempo_cpu\":%.2f,\"memoria_rss_kb\":%lu}",
        name_esc,
        pid,
        cpu_s,
        rss_kb
    );
}

static void handle_client(int fd) {
    char req[MAX_REQ];
    ssize_t n = recv(fd, req, sizeof(req) - 1, 0);
    if (n <= 0) {
        return;
    }
    req[n] = '\0';

    char method[16] = {0};
    char path[1024] = {0};
    if (sscanf(req, "%15s %1023s", method, path) != 2) {
        send_json_msg(fd, 400, "Solicitud invalida");
        return;
    }

    if (strcmp(method, "OPTIONS") == 0) {
        send_response(fd, 200, "application/json", "{}");
        return;
    }

    char token[96] = {0};
    extract_bearer_token(req, token, sizeof(token));

    char user[64] = {0};
    char role[16] = {0};
    int is_auth = get_session_from_token(token, user, sizeof(user), role, sizeof(role));

    const char *body = strstr(req, "\r\n\r\n");
    body = body ? (body + 4) : "";

    char resp[MAX_RESP];
    resp[0] = '\0';

    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/login") == 0) {
        char username[64] = {0}, password[128] = {0};
        if (!extract_json_field(body, "username", username, sizeof(username)) ||
            !extract_json_field(body, "password", password, sizeof(password))) {
            send_json_msg(fd, 400, "Credenciales incompletas");
            return;
        }

        if (!authenticate_with_pam(username, password)) {
            send_json_msg(fd, 401, "Autenticacion PAM fallida");
            return;
        }

        char user_role[16] = {0};
        if (!resolve_role(username, user_role, sizeof(user_role))) {
            send_json_msg(fd, 403, "Usuario sin grupo permitido");
            return;
        }

        char session_token[65] = {0};
        create_session(username, user_role, session_token);

        snprintf(
            resp,
            sizeof(resp),
            "{\"ok\":true,\"token\":\"%s\",\"username\":\"%s\",\"role\":\"%s\"}",
            session_token,
            username,
            user_role
        );
        send_response(fd, 200, "application/json", resp);
        return;
    }

    if (!is_auth) {
        send_json_msg(fd, 401, "Token requerido");
        return;
    }

    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/metrics") == 0) {
        build_metrics_json(resp, sizeof(resp));
        send_response(fd, 200, "application/json", resp);
        return;
    }

    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/alerts") == 0) {
        build_alerts_json(resp, sizeof(resp));
        send_response(fd, 200, "application/json", resp);
        return;
    }

    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/files") == 0) {
        build_files_json(resp, sizeof(resp));
        send_response(fd, 200, "application/json", resp);
        return;
    }

    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/threats") == 0) {
        build_threats_json(resp, sizeof(resp));
        send_response(fd, 200, "application/json", resp);
        return;
    }

    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/me") == 0) {
        build_me_json(user, role, resp, sizeof(resp));
        send_response(fd, 200, "application/json", resp);
        return;
    }

    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/report/summary") == 0) {
        build_summary_report_json(user, role, resp, sizeof(resp));
        send_response(fd, 200, "application/json", resp);
        return;
    }

    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/quarantine") == 0) {
        if (strcmp(role, "admin") != 0) {
            send_json_msg(fd, 403, "Solo admin puede listar cuarentena");
            return;
        }

        build_quarantine_json(resp, sizeof(resp));
        send_response(fd, 200, "application/json", resp);
        return;
    }

    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/scan/once") == 0) {
        if (strcmp(role, "admin") != 0) {
            send_json_msg(fd, 403, "Solo admin puede ejecutar escaneo puntual");
            return;
        }

        scan_once();
        push_alert("archivo", "LOW", "Escaneo puntual ejecutado por administrador");
        send_response(fd, 200, "application/json", "{\"ok\":true}");
        return;
    }

    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/quarantine/add") == 0) {
        if (strcmp(role, "admin") != 0) {
            send_json_msg(fd, 403, "Solo admin puede agregar cuarentena");
            return;
        }

        char file_path[MAX_PATH] = {0};
        if (!extract_json_field(body, "path", file_path, sizeof(file_path)) || file_path[0] == '\0') {
            send_json_msg(fd, 400, "Path requerido");
            return;
        }

        if (kcall_quarantine_file(file_path) != 0) {
            send_json_msg(fd, 400, "No se pudo agregar a cuarentena");
            return;
        }

        unmark_restored_path(file_path);

        struct stat st;
        char hash[65] = "manual";
        long mtime = (long)time(NULL);
        if (stat(file_path, &st) == 0) {
            mtime = st.st_mtime;
            (void)compute_sha256sum(file_path, hash);
        }
        update_file_record(file_path, hash, mtime, "cuarentena");
        push_alert("archivo", "HIGH", "Archivo agregado manualmente a cuarentena");

        send_response(fd, 200, "application/json", "{\"ok\":true}");
        return;
    }

    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/quarantine/restore") == 0) {
        if (strcmp(role, "admin") != 0) {
            send_json_msg(fd, 403, "Solo admin puede restaurar cuarentena");
            return;
        }

        char file_path[MAX_PATH] = {0};
        if (!extract_json_field(body, "path", file_path, sizeof(file_path)) || file_path[0] == '\0') {
            send_json_msg(fd, 400, "Path requerido");
            return;
        }

        if (kcall_restore_file(file_path) != 0) {
            send_json_msg(fd, 400, "No se pudo restaurar archivo");
            return;
        }

        struct stat st;
        char hash[65] = "restored";
        long mtime = (long)time(NULL);
        if (stat(file_path, &st) == 0) {
            mtime = st.st_mtime;
            (void)compute_sha256sum(file_path, hash);
        }
        update_file_record(file_path, hash, mtime, "limpio");
        mark_restored_path(file_path);
        push_alert("archivo", "LOW", "Archivo restaurado manualmente por administrador");

        send_response(fd, 200, "application/json", "{\"ok\":true}");
        return;
    }

    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/scan/start") == 0) {
        if (strcmp(role, "admin") != 0) {
            send_json_msg(fd, 403, "Solo admin puede activar escaneo");
            return;
        }

        pthread_mutex_lock(&g_state.lock);
        g_state.scan_enabled = 1;
        pthread_mutex_unlock(&g_state.lock);

        push_alert("archivo", "LOW", "Escaneo activado por administrador");
        send_response(fd, 200, "application/json", "{\"ok\":true}");
        return;
    }

    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/scan/stop") == 0) {
        if (strcmp(role, "admin") != 0) {
            send_json_msg(fd, 403, "Solo admin puede desactivar escaneo");
            return;
        }

        pthread_mutex_lock(&g_state.lock);
        g_state.scan_enabled = 0;
        pthread_mutex_unlock(&g_state.lock);

        push_alert("archivo", "LOW", "Escaneo desactivado por administrador");
        send_response(fd, 200, "application/json", "{\"ok\":true}");
        return;
    }

    if (strcmp(method, "GET") == 0 && strncmp(path, "/api/process", 12) == 0) {
        if (strcmp(role, "admin") != 0) {
            send_json_msg(fd, 403, "Solo admin puede consultar proceso por PID");
            return;
        }

        int pid = parse_pid_from_path(path);
        if (pid <= 0) {
            send_json_msg(fd, 400, "PID invalido");
            return;
        }

        build_process_json(pid, resp, sizeof(resp));
        send_response(fd, 200, "application/json", resp);
        return;
    }

    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/admin/users/create") == 0) {
        if (strcmp(role, "admin") != 0) {
            send_json_msg(fd, 403, "Solo admin puede crear usuarios");
            return;
        }

        char username[64] = {0};
        char password[128] = {0};
        char new_role[16] = {0};
        if (!extract_json_field(body, "username", username, sizeof(username)) ||
            !extract_json_field(body, "password", password, sizeof(password)) ||
            !extract_json_field(body, "role", new_role, sizeof(new_role))) {
            send_json_msg(fd, 400, "Datos incompletos para crear usuario");
            return;
        }

        char errbuf[512] = {0};
        if (create_system_user_account(username, password, new_role, errbuf, sizeof(errbuf)) != 0) {
            send_json_msg(fd, 400, errbuf[0] ? errbuf : "No se pudo crear el usuario");
            return;
        }

        if (strcmp(new_role, "admin") == 0) {
            push_alert("usuario", "MEDIUM", "Administrador creado desde dashboard");
        } else {
            push_alert("usuario", "LOW", "Usuario comun creado desde dashboard");
        }

        snprintf(
            resp,
            sizeof(resp),
            "{\"ok\":true,\"username\":\"%s\",\"role\":\"%s\",\"message\":\"Usuario creado correctamente\"}",
            username,
            new_role
        );
        send_response(fd, 200, "application/json", resp);
        return;
    }

    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/admin/users") == 0) {
        if (strcmp(role, "admin") != 0) {
            send_json_msg(fd, 403, "Solo admin puede listar usuarios");
            return;
        }

        build_admin_users_json(user, resp, sizeof(resp));
        send_response(fd, 200, "application/json", resp);
        return;
    }

    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/admin/users/delete") == 0) {
        if (strcmp(role, "admin") != 0) {
            send_json_msg(fd, 403, "Solo admin puede eliminar usuarios");
            return;
        }

        char username[64] = {0};
        if (!extract_json_field(body, "username", username, sizeof(username))) {
            send_json_msg(fd, 400, "Username requerido");
            return;
        }

        char deleted_role[16] = {0};
        char errbuf[512] = {0};
        if (delete_system_user_account(username, user, deleted_role, sizeof(deleted_role), errbuf, sizeof(errbuf)) != 0) {
            send_json_msg(fd, 400, errbuf[0] ? errbuf : "No se pudo eliminar el usuario");
            return;
        }

        if (strcmp(deleted_role, "admin") == 0) {
            push_alert("usuario", "HIGH", "Administrador eliminado desde dashboard");
        } else {
            push_alert("usuario", "MEDIUM", "Usuario comun eliminado desde dashboard");
        }

        snprintf(
            resp,
            sizeof(resp),
            "{\"ok\":true,\"username\":\"%s\",\"role\":\"%s\",\"message\":\"Usuario eliminado correctamente\"}",
            username,
            deleted_role
        );
        send_response(fd, 200, "application/json", resp);
        return;
    }

    send_json_msg(fd, 404, "Ruta no encontrada");
}

static void on_signal(int sig) {
    (void)sig;
    g_running = 0;
    if (g_server_fd >= 0) {
        close(g_server_fd);
        g_server_fd = -1;
    }
}

static int run_server(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)g_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        close(fd);
        return -1;
    }

    if (listen(fd, 16) != 0) {
        perror("listen");
        close(fd);
        return -1;
    }

    g_server_fd = fd;
    printf("[daemon] API escuchando en puerto %d\n", g_port);
    printf("[daemon] Directorio de escaneo: %s\n", g_watch_dir);
    printf("[daemon] Blacklist: %s\n", g_blacklist_path);

    while (g_running) {
        struct sockaddr_in cli;
        socklen_t len = sizeof(cli);
        int cfd = accept(fd, (struct sockaddr *)&cli, &len);
        if (cfd < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        handle_client(cfd);
        close(cfd);
    }

    close(fd);
    g_server_fd = -1;
    return 0;
}

static void usage(const char *prog) {
    printf("Uso: %s [-p puerto] [-w dir_escaneo] [-b blacklist] [-m monitor_s] [-s scan_s] [-d]\n", prog);
}

int main(int argc, char **argv) {
    int opt;
    while ((opt = getopt(argc, argv, "p:w:b:m:s:dh")) != -1) {
        switch (opt) {
            case 'p':
                g_port = atoi(optarg);
                break;
            case 'w':
                snprintf(g_watch_dir, sizeof(g_watch_dir), "%s", optarg);
                break;
            case 'b':
                snprintf(g_blacklist_path, sizeof(g_blacklist_path), "%s", optarg);
                break;
            case 'm':
                g_monitor_interval = atoi(optarg);
                break;
            case 's':
                g_scan_interval = atoi(optarg);
                break;
            case 'd':
                g_daemon_mode = 1;
                break;
            case 'h':
            default:
                usage(argv[0]);
                return 0;
        }
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    if (load_blacklist(g_blacklist_path) != 0) {
        fprintf(stderr, "[daemon] No se pudo leer blacklist en %s\n", g_blacklist_path);
    }

    if (g_daemon_mode) {
        if (daemon(0, 0) != 0) {
            perror("daemon");
            return 1;
        }
    }

    pthread_t th_monitor;
    pthread_t th_scan;

    if (pthread_create(&th_monitor, NULL, monitor_thread, NULL) != 0) {
        perror("pthread_create monitor");
        return 1;
    }

    if (pthread_create(&th_scan, NULL, scan_thread, NULL) != 0) {
        perror("pthread_create scan");
        g_running = 0;
        pthread_join(th_monitor, NULL);
        return 1;
    }

    int rc = run_server();

    g_running = 0;
    pthread_join(th_monitor, NULL);
    pthread_join(th_scan, NULL);

    return rc == 0 ? 0 : 1;
}
