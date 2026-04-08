#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    long segments;
    long size_kb;
    long rss_kb;
    long pss_kb;
    long shared_clean_kb;
    long shared_dirty_kb;
    long private_clean_kb;
    long private_dirty_kb;
    long referenced_kb;
} smaps_bucket_t;

typedef struct {
    unsigned long start;
    unsigned long end;
    char perms[8];
    char path[PATH_MAX];
    long size_kb;
    long rss_kb;
    long pss_kb;
    long shared_clean_kb;
    long shared_dirty_kb;
    long private_clean_kb;
    long private_dirty_kb;
    long referenced_kb;
} smaps_segment_t;

#define MAX_SMAPS_SEGMENTS 256

typedef struct {
    long mem_free_kb;
    long mem_avail_kb;
    long rss_kb;
    long pss_kb;
    long maps_count;
    long vm_area_active_objs;
    long vm_area_obj_size;
    long anon_vma_active_objs;
    long anon_vma_obj_size;
    long vmap_area_active_objs;
    long vmap_area_obj_size;
    long dentry_active_objs;
    long dentry_obj_size;
    long inode_active_objs;
    long inode_obj_size;
    smaps_bucket_t so_total;
    smaps_bucket_t so_rx;
    smaps_bucket_t so_r;
    smaps_bucket_t so_rw;
    smaps_bucket_t so_other;
    smaps_segment_t so_segments[MAX_SMAPS_SEGMENTS];
    int so_segment_count;
} snapshot_t;

static long read_value_from_file(const char *path, const char *key) {
    FILE *fp = fopen(path, "r");
    char line[512];
    size_t key_len = strlen(key);

    if (!fp) {
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, key, key_len) == 0) {
            long value = -1;
            if (sscanf(line + key_len, "%ld", &value) == 1) {
                fclose(fp);
                return value;
            }
        }
    }

    fclose(fp);
    return -1;
}

static long count_lines(const char *path) {
    FILE *fp = fopen(path, "r");
    char line[512];
    long count = 0;

    if (!fp) {
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        count++;
    }

    fclose(fp);
    return count;
}

static void read_slab_entry(const char *name, long *active_objs, long *obj_size) {
    FILE *fp = fopen("/proc/slabinfo", "r");
    char line[512];

    *active_objs = -1;
    *obj_size = -1;

    if (!fp) {
        return;
    }

    while (fgets(line, sizeof(line), fp)) {
        char slab_name[128];
        long active = 0;
        long total = 0;
        long size = 0;

        if (sscanf(line, "%127s %ld %ld %ld", slab_name, &active, &total, &size) == 4) {
            if (strcmp(slab_name, name) == 0) {
                *active_objs = active;
                *obj_size = size;
                fclose(fp);
                return;
            }
        }
    }

    fclose(fp);
}

static const char *base_name(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static void add_smaps_value(smaps_bucket_t *bucket, const char *key, long value) {
    if (strcmp(key, "Size:") == 0) {
        bucket->size_kb += value;
    } else if (strcmp(key, "Rss:") == 0) {
        bucket->rss_kb += value;
    } else if (strcmp(key, "Pss:") == 0) {
        bucket->pss_kb += value;
    } else if (strcmp(key, "Shared_Clean:") == 0) {
        bucket->shared_clean_kb += value;
    } else if (strcmp(key, "Shared_Dirty:") == 0) {
        bucket->shared_dirty_kb += value;
    } else if (strcmp(key, "Private_Clean:") == 0) {
        bucket->private_clean_kb += value;
    } else if (strcmp(key, "Private_Dirty:") == 0) {
        bucket->private_dirty_kb += value;
    } else if (strcmp(key, "Referenced:") == 0) {
        bucket->referenced_kb += value;
    }
}

static smaps_bucket_t *select_bucket(snapshot_t *snap, const char *perms) {
    if (strncmp(perms, "r-x", 3) == 0) {
        return &snap->so_rx;
    }
    if (strncmp(perms, "r--", 3) == 0) {
        return &snap->so_r;
    }
    if (strncmp(perms, "rw-", 3) == 0) {
        return &snap->so_rw;
    }
    return &snap->so_other;
}

static void add_segment_value(smaps_segment_t *segment, const char *key, long value) {
    if (strcmp(key, "Size:") == 0) {
        segment->size_kb += value;
    } else if (strcmp(key, "Rss:") == 0) {
        segment->rss_kb += value;
    } else if (strcmp(key, "Pss:") == 0) {
        segment->pss_kb += value;
    } else if (strcmp(key, "Shared_Clean:") == 0) {
        segment->shared_clean_kb += value;
    } else if (strcmp(key, "Shared_Dirty:") == 0) {
        segment->shared_dirty_kb += value;
    } else if (strcmp(key, "Private_Clean:") == 0) {
        segment->private_clean_kb += value;
    } else if (strcmp(key, "Private_Dirty:") == 0) {
        segment->private_dirty_kb += value;
    } else if (strcmp(key, "Referenced:") == 0) {
        segment->referenced_kb += value;
    }
}

static void read_smaps_for_library(snapshot_t *snap, const char *lib_path) {
    FILE *fp = fopen("/proc/self/smaps", "r");
    char line[1024];
    char target_name[PATH_MAX];
    int current_matches = 0;
    smaps_bucket_t *current_bucket = NULL;
    smaps_segment_t *current_segment = NULL;

    if (!fp) {
        return;
    }

    snprintf(target_name, sizeof(target_name), "%s", base_name(lib_path));

    while (fgets(line, sizeof(line), fp)) {
        unsigned long start = 0;
        unsigned long end = 0;
        unsigned long offset = 0;
        unsigned int dev_major = 0;
        unsigned int dev_minor = 0;
        unsigned long inode = 0;
        char perms[8] = {0};
        char path[PATH_MAX] = {0};

        if (sscanf(line, "%lx-%lx %7s %lx %x:%x %lu %1023[^\n]", &start, &end, perms, &offset, &dev_major, &dev_minor, &inode, path) >= 7) {
            const char *trimmed = path;
            while (*trimmed == ' ') {
                trimmed++;
            }

            current_matches = (*trimmed != '\0' && strstr(trimmed, target_name) != NULL);
            current_bucket = current_matches ? select_bucket(snap, perms) : NULL;
            current_segment = NULL;
            if (current_bucket) {
                current_bucket->segments++;
                snap->so_total.segments++;
                if (snap->so_segment_count < MAX_SMAPS_SEGMENTS) {
                    current_segment = &snap->so_segments[snap->so_segment_count++];
                    memset(current_segment, 0, sizeof(*current_segment));
                    current_segment->start = start;
                    current_segment->end = end;
                    snprintf(current_segment->perms, sizeof(current_segment->perms), "%s", perms);
                    snprintf(current_segment->path, sizeof(current_segment->path), "%s", trimmed);
                }
            }
            continue;
        }

        if (current_matches && current_bucket) {
            char key[64];
            long value = 0;

            if (sscanf(line, "%63s %ld", key, &value) == 2) {
                add_smaps_value(&snap->so_total, key, value);
                add_smaps_value(current_bucket, key, value);
                if (current_segment) {
                    add_segment_value(current_segment, key, value);
                }
            }
        }
    }

    fclose(fp);
}

static void take_snapshot(snapshot_t *snap, const char *lib_path) {
    memset(snap, 0, sizeof(*snap));
    snap->mem_free_kb = read_value_from_file("/proc/meminfo", "MemFree:");
    snap->mem_avail_kb = read_value_from_file("/proc/meminfo", "MemAvailable:");
    snap->rss_kb = read_value_from_file("/proc/self/smaps_rollup", "Rss:");
    snap->pss_kb = read_value_from_file("/proc/self/smaps_rollup", "Pss:");
    snap->maps_count = count_lines("/proc/self/maps");
    read_slab_entry("vm_area_struct", &snap->vm_area_active_objs, &snap->vm_area_obj_size);
    read_slab_entry("anon_vma", &snap->anon_vma_active_objs, &snap->anon_vma_obj_size);
    read_slab_entry("vmap_area", &snap->vmap_area_active_objs, &snap->vmap_area_obj_size);
    read_slab_entry("dentry", &snap->dentry_active_objs, &snap->dentry_obj_size);
    read_slab_entry("inode_cache", &snap->inode_active_objs, &snap->inode_obj_size);
    read_smaps_for_library(snap, lib_path);
}

static void print_smaps_bucket_delta(const char *label, const smaps_bucket_t *before, const smaps_bucket_t *after) {
    printf("%s: segments %+ld, Size %+ld kB, Rss %+ld kB, Pss %+ld kB, Shared_Clean %+ld kB, Shared_Dirty %+ld kB, Private_Clean %+ld kB, Private_Dirty %+ld kB, Referenced %+ld kB\n",
           label,
           after->segments - before->segments,
           after->size_kb - before->size_kb,
           after->rss_kb - before->rss_kb,
           after->pss_kb - before->pss_kb,
           after->shared_clean_kb - before->shared_clean_kb,
           after->shared_dirty_kb - before->shared_dirty_kb,
           after->private_clean_kb - before->private_clean_kb,
           after->private_dirty_kb - before->private_dirty_kb,
           after->referenced_kb - before->referenced_kb);
}

static int segment_identity_equal(const smaps_segment_t *a, const smaps_segment_t *b) {
    return a->start == b->start && a->end == b->end && strcmp(a->perms, b->perms) == 0 && strcmp(a->path, b->path) == 0;
}

static const smaps_segment_t *find_segment(const snapshot_t *snap, const smaps_segment_t *target) {
    int i;
    for (i = 0; i < snap->so_segment_count; i++) {
        if (segment_identity_equal(&snap->so_segments[i], target)) {
            return &snap->so_segments[i];
        }
    }
    return NULL;
}

static void print_segment_delta(const char *prefix, const smaps_segment_t *before, const smaps_segment_t *after) {
    long before_size = before ? before->size_kb : 0;
    long before_rss = before ? before->rss_kb : 0;
    long before_pss = before ? before->pss_kb : 0;
    long before_shared_clean = before ? before->shared_clean_kb : 0;
    long before_shared_dirty = before ? before->shared_dirty_kb : 0;
    long before_private_clean = before ? before->private_clean_kb : 0;
    long before_private_dirty = before ? before->private_dirty_kb : 0;
    long before_referenced = before ? before->referenced_kb : 0;
    const smaps_segment_t *segment = after ? after : before;

    printf("%s%08lx-%08lx %s %s\n",
           prefix,
           segment->start,
           segment->end,
           segment->perms,
           segment->path);
    printf("%s  Size %+ld kB, Rss %+ld kB, Pss %+ld kB, Shared_Clean %+ld kB, Shared_Dirty %+ld kB, Private_Clean %+ld kB, Private_Dirty %+ld kB, Referenced %+ld kB\n",
           prefix,
           (after ? after->size_kb : 0) - before_size,
           (after ? after->rss_kb : 0) - before_rss,
           (after ? after->pss_kb : 0) - before_pss,
           (after ? after->shared_clean_kb : 0) - before_shared_clean,
           (after ? after->shared_dirty_kb : 0) - before_shared_dirty,
           (after ? after->private_clean_kb : 0) - before_private_clean,
           (after ? after->private_dirty_kb : 0) - before_private_dirty,
           (after ? after->referenced_kb : 0) - before_referenced);
}

static void print_smaps_segment_deltas(const snapshot_t *before, const snapshot_t *after) {
    int i;

    printf("smaps segment details for target .so:\n");
    for (i = 0; i < after->so_segment_count; i++) {
        const smaps_segment_t *after_segment = &after->so_segments[i];
        const smaps_segment_t *before_segment = find_segment(before, after_segment);
        print_segment_delta("  ", before_segment, after_segment);
    }

    for (i = 0; i < before->so_segment_count; i++) {
        const smaps_segment_t *before_segment = &before->so_segments[i];
        if (!find_segment(after, before_segment)) {
            print_segment_delta("  ", before_segment, NULL);
        }
    }
}

static void print_delta(const char *label, const snapshot_t *before, const snapshot_t *after, int iterations) {
    long vm_area_bytes = -1;
    long anon_vma_bytes = -1;
    long vmap_area_bytes = -1;
    long dentry_bytes = -1;
    long inode_bytes = -1;

    if (before->vm_area_active_objs >= 0 && after->vm_area_active_objs >= 0 && after->vm_area_obj_size > 0) {
        vm_area_bytes = (after->vm_area_active_objs - before->vm_area_active_objs) * after->vm_area_obj_size;
    }
    if (before->anon_vma_active_objs >= 0 && after->anon_vma_active_objs >= 0 && after->anon_vma_obj_size > 0) {
        anon_vma_bytes = (after->anon_vma_active_objs - before->anon_vma_active_objs) * after->anon_vma_obj_size;
    }
    if (before->vmap_area_active_objs >= 0 && after->vmap_area_active_objs >= 0 && after->vmap_area_obj_size > 0) {
        vmap_area_bytes = (after->vmap_area_active_objs - before->vmap_area_active_objs) * after->vmap_area_obj_size;
    }
    if (before->dentry_active_objs >= 0 && after->dentry_active_objs >= 0 && after->dentry_obj_size > 0) {
        dentry_bytes = (after->dentry_active_objs - before->dentry_active_objs) * after->dentry_obj_size;
    }
    if (before->inode_active_objs >= 0 && after->inode_active_objs >= 0 && after->inode_obj_size > 0) {
        inode_bytes = (after->inode_active_objs - before->inode_active_objs) * after->inode_obj_size;
    }

    printf("\n== %s ==\n", label);
    printf("iterations: %d\n", iterations);
    printf("self maps delta: %ld\n", after->maps_count - before->maps_count);
    printf("self rss delta: %ld kB\n", after->rss_kb - before->rss_kb);
    printf("self pss delta: %ld kB\n", after->pss_kb - before->pss_kb);
    printf("MemFree delta: %ld kB\n", after->mem_free_kb - before->mem_free_kb);
    printf("MemAvailable delta: %ld kB\n", after->mem_avail_kb - before->mem_avail_kb);

    if (vm_area_bytes >= 0) {
        printf("vm_area_struct delta: %ld objs, about %ld bytes total", after->vm_area_active_objs - before->vm_area_active_objs, vm_area_bytes);
        if (iterations > 0) {
            printf(", about %.2f bytes/load", (double)vm_area_bytes / iterations);
        }
        printf("\n");
    } else {
        printf("vm_area_struct delta: unavailable in /proc/slabinfo on this kernel\n");
    }

    if (anon_vma_bytes >= 0) {
        printf("anon_vma delta: %ld objs, about %ld bytes total", after->anon_vma_active_objs - before->anon_vma_active_objs, anon_vma_bytes);
        if (iterations > 0) {
            printf(", about %.2f bytes/load", (double)anon_vma_bytes / iterations);
        }
        printf(" (related to anonymous VMAs, not a direct dlopen-only cost)\n");
    } else {
        printf("anon_vma delta: unavailable\n");
    }

    if (vmap_area_bytes >= 0) {
        printf("vmap_area delta: %ld objs, about %ld bytes total", after->vmap_area_active_objs - before->vmap_area_active_objs, vmap_area_bytes);
        if (iterations > 0) {
            printf(", about %.2f bytes/load", (double)vmap_area_bytes / iterations);
        }
        printf(" (kernel vmalloc metadata, usually not the main dlopen signal)\n");
    } else {
        printf("vmap_area delta: unavailable\n");
    }

    if (dentry_bytes >= 0) {
        printf("dentry delta: %ld objs, about %ld bytes total", after->dentry_active_objs - before->dentry_active_objs, dentry_bytes);
        if (iterations > 0) {
            printf(", about %.2f bytes/load", (double)dentry_bytes / iterations);
        }
        printf("\n");
    } else {
        printf("dentry delta: unavailable\n");
    }

    if (inode_bytes >= 0) {
        printf("inode_cache delta: %ld objs, about %ld bytes total", after->inode_active_objs - before->inode_active_objs, inode_bytes);
        if (iterations > 0) {
            printf(", about %.2f bytes/load", (double)inode_bytes / iterations);
        }
        printf("\n");
    } else {
        printf("inode_cache delta: unavailable\n");
    }

    printf("smaps details for target .so:\n");
    print_smaps_bucket_delta("  total", &before->so_total, &after->so_total);
    print_smaps_bucket_delta("  r-x*", &before->so_rx, &after->so_rx);
    print_smaps_bucket_delta("  r--*", &before->so_r, &after->so_r);
    print_smaps_bucket_delta("  rw-*", &before->so_rw, &after->so_rw);
    print_smaps_bucket_delta("  other", &before->so_other, &after->so_other);
    print_smaps_segment_deltas(before, after);
}

static long file_size_bytes(const char *path) {
    FILE *fp = fopen(path, "rb");
    long size;

    if (!fp) {
        return -1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }

    size = ftell(fp);
    fclose(fp);
    return size;
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <path-to-so> [count] [mode]\n", prog);
    fprintf(stderr, "  mode: dlmopen (default) or dlopen\n");
}

int main(int argc, char **argv) {
    const char *lib_path;
    int count = 1000;
    int use_dlmopen = 1;
    void **handles;
    snapshot_t before_load;
    snapshot_t after_load;
    snapshot_t after_close;
    long page_size = sysconf(_SC_PAGESIZE);
    int i;

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    lib_path = argv[1];
    if (argc >= 3) {
        count = atoi(argv[2]);
        if (count <= 0) {
            fprintf(stderr, "count must be > 0\n");
            return 1;
        }
    }
    if (argc >= 4) {
        if (strcmp(argv[3], "dlopen") == 0) {
            use_dlmopen = 0;
        } else if (strcmp(argv[3], "dlmopen") == 0) {
            use_dlmopen = 1;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    handles = calloc((size_t)count, sizeof(void *));
    if (!handles) {
        perror("calloc");
        return 1;
    }

    printf("library: %s\n", lib_path);
    printf("file size: %ld bytes\n", file_size_bytes(lib_path));
    printf("page size: %ld bytes\n", page_size);
    printf("mode: %s\n", use_dlmopen ? "dlmopen (independent namespaces)" : "dlopen (same namespace, refcount only)");

    take_snapshot(&before_load, lib_path);

    for (i = 0; i < count; i++) {
        if (use_dlmopen) {
            handles[i] = dlmopen(LM_ID_NEWLM, lib_path, RTLD_NOW | RTLD_LOCAL);
        } else {
            handles[i] = dlopen(lib_path, RTLD_NOW | RTLD_LOCAL);
        }

        if (!handles[i]) {
            fprintf(stderr, "load failed at iteration %d: %s\n", i, dlerror());
            count = i;
            break;
        }
    }

    take_snapshot(&after_load, lib_path);

    for (i = 0; i < count; i++) {
        if (handles[i] && dlclose(handles[i]) != 0) {
            fprintf(stderr, "dlclose failed at iteration %d: %s\n", i, dlerror());
        }
    }

    take_snapshot(&after_close, lib_path);

    print_delta("after load", &before_load, &after_load, count);
    print_delta("after close", &before_load, &after_close, count);

    free(handles);
    return 0;
}
