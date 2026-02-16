#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

// Global log level
static log_level_t g_log_level = LOG_INFO;

void log_set_level(log_level_t level) {
    g_log_level = level;
}

void log_msg(log_level_t level, const char *fmt, ...) {
    if (level < g_log_level) {
        return;
    }
    
    const char *level_str;
    switch (level) {
        case LOG_DEBUG: level_str = "DEBUG"; break;
        case LOG_INFO:  level_str = "INFO "; break;
        case LOG_WARN:  level_str = "WARN "; break;
        case LOG_ERROR: level_str = "ERROR"; break;
        default:        level_str = "?????"; break;
    }
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    
    fprintf(stderr, "[%s] [%s] ", time_buf, level_str);
    
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    
    fprintf(stderr, "\n");
}

ldmd_error_t utils_mkdir_p(const char *path) {
    char tmp[LDMD_MAX_PATH];
    char *p = NULL;
    size_t len;
    
    ldmd_strlcpy(tmp, path, sizeof(tmp));
    len = strlen(tmp);
    
    if (tmp[len - 1] == '/') {
        tmp[len - 1] = '\0';
    }
    
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                LOG_ERROR("Failed to create directory: %s (%s)", tmp, strerror(errno));
                return LDMD_ERROR_IO;
            }
            *p = '/';
        }
    }
    
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        LOG_ERROR("Failed to create directory: %s (%s)", tmp, strerror(errno));
        return LDMD_ERROR_IO;
    }
    
    return LDMD_OK;
}

bool utils_file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

bool utils_is_directory(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return false;
    }
    return S_ISDIR(st.st_mode);
}

ldmd_error_t utils_read_file(const char *path, char **content_out) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        LOG_ERROR("Failed to open file: %s", path);
        return LDMD_ERROR_IO;
    }
    
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    char *content = malloc(size + 1);
    if (!content) {
        fclose(fp);
        return LDMD_ERROR_MEMORY;
    }
    
    size_t read = fread(content, 1, size, fp);
    content[read] = '\0';
    
    fclose(fp);
    *content_out = content;
    return LDMD_OK;
}

ldmd_error_t utils_write_file(const char *path, const char *content) {
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        LOG_ERROR("Failed to create file: %s", path);
        return LDMD_ERROR_IO;
    }
    
    size_t len = strlen(content);
    size_t written = fwrite(content, 1, len, fp);
    fclose(fp);
    
    if (written != len) {
        LOG_ERROR("Failed to write file: %s", path);
        return LDMD_ERROR_IO;
    }
    
    return LDMD_OK;
}

ldmd_error_t utils_delete_file(const char *path) {
    if (unlink(path) != 0 && errno != ENOENT) {
        LOG_ERROR("Failed to delete file: %s (%s)", path, strerror(errno));
        return LDMD_ERROR_IO;
    }
    return LDMD_OK;
}

ldmd_error_t utils_rmdir_r(const char *path) {
    DIR *dir = opendir(path);
    if (!dir) {
        return LDMD_ERROR_IO;
    }
    
    struct dirent *entry;
    char filepath[LDMD_MAX_PATH];
    
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        snprintf(filepath, sizeof(filepath), "%s/%s", path, entry->d_name);
        
        if (utils_is_directory(filepath)) {
            utils_rmdir_r(filepath);
        } else {
            utils_delete_file(filepath);
        }
    }
    
    closedir(dir);
    rmdir(path);
    
    return LDMD_OK;
}

const char *utils_get_extension(const char *path) {
    const char *dot = strrchr(path, '.');
    if (!dot || dot == path) {
        return "";
    }
    return dot;
}

bool utils_extension_allowed(const char *ext, const char *allowed_list) {
    if (!ext || !allowed_list) {
        return false;
    }
    
    char list_copy[512];
    ldmd_strlcpy(list_copy, allowed_list, sizeof(list_copy));
    
    char *token = strtok(list_copy, ",");
    while (token) {
        char *trimmed = utils_trim(token);
        if (strcasecmp(ext, trimmed) == 0) {
            return true;
        }
        token = strtok(NULL, ",");
    }
    
    return false;
}

time_t utils_now(void) {
    return time(NULL);
}

char *utils_format_time(time_t ts, char *buf, size_t size) {
    struct tm *tm_info = localtime(&ts);
    strftime(buf, size, "%Y-%m-%d %H:%M:%S", tm_info);
    return buf;
}

ldmd_error_t utils_url_encode(const char *str, char **encoded_out) {
    if (!str) {
        *encoded_out = utils_strdup("");
        return LDMD_OK;
    }
    
    size_t len = strlen(str);
    char *encoded = malloc(len * 3 + 1);
    if (!encoded) {
        return LDMD_ERROR_MEMORY;
    }
    
    char *p = encoded;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = str[i];
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            *p++ = c;
        } else {
            sprintf(p, "%%%02X", c);
            p += 3;
        }
    }
    *p = '\0';
    
    *encoded_out = encoded;
    return LDMD_OK;
}

ldmd_error_t utils_url_decode(const char *str, char **decoded_out) {
    if (!str) {
        *decoded_out = utils_strdup("");
        return LDMD_OK;
    }
    
    size_t len = strlen(str);
    char *decoded = malloc(len + 1);
    if (!decoded) {
        return LDMD_ERROR_MEMORY;
    }
    
    char *p = decoded;
    for (size_t i = 0; i < len; i++) {
        if (str[i] == '%' && i + 2 < len) {
            char hex[3] = { str[i+1], str[i+2], '\0' };
            *p++ = (char)strtol(hex, NULL, 16);
            i += 2;
        } else if (str[i] == '+') {
            *p++ = ' ';
        } else {
            *p++ = str[i];
        }
    }
    *p = '\0';
    
    *decoded_out = decoded;
    return LDMD_OK;
}

char *utils_trim(char *str) {
    if (!str) return str;
    
    // Trim leading
    while (isspace((unsigned char)*str)) str++;
    
    if (*str == '\0') return str;
    
    // Trim trailing
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    
    return str;
}

char *utils_strdup(const char *str) {
    if (!str) return NULL;
    size_t len = strlen(str) + 1;
    char *dup = malloc(len);
    if (dup) {
        memcpy(dup, str, len);
    }
    return dup;
}

int utils_snprintf(char *buf, size_t size, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int ret = vsnprintf(buf, size, fmt, args);
    va_end(args);
    return ret;
}
