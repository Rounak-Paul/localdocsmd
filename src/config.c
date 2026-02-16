#include "config.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Simple INI parser
typedef struct {
    char section[64];
    char key[64];
    char value[512];
} ini_entry_t;

typedef struct {
    ini_entry_t *entries;
    int count;
    int capacity;
} ini_file_t;

static ini_file_t *ini_parse(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        LOG_ERROR("Failed to open config file: %s", path);
        return NULL;
    }
    
    ini_file_t *ini = calloc(1, sizeof(ini_file_t));
    if (!ini) {
        fclose(fp);
        return NULL;
    }
    
    ini->capacity = 64;
    ini->entries = calloc(ini->capacity, sizeof(ini_entry_t));
    if (!ini->entries) {
        free(ini);
        fclose(fp);
        return NULL;
    }
    
    char line[1024];
    char current_section[64] = "";
    
    while (fgets(line, sizeof(line), fp)) {
        char *p = utils_trim(line);
        
        // Skip empty lines and comments
        if (*p == '\0' || *p == '#' || *p == ';') {
            continue;
        }
        
        // Section header
        if (*p == '[') {
            char *end = strchr(p, ']');
            if (end) {
                *end = '\0';
                ldmd_strlcpy(current_section, p + 1, sizeof(current_section));
            }
            continue;
        }
        
        // Key = Value
        char *eq = strchr(p, '=');
        if (eq) {
            *eq = '\0';
            char *key = utils_trim(p);
            char *value = utils_trim(eq + 1);
            
            // Expand capacity if needed
            if (ini->count >= ini->capacity) {
                ini->capacity *= 2;
                ini->entries = realloc(ini->entries, ini->capacity * sizeof(ini_entry_t));
            }
            
            ini_entry_t *entry = &ini->entries[ini->count++];
            ldmd_strlcpy(entry->section, current_section, sizeof(entry->section));
            ldmd_strlcpy(entry->key, key, sizeof(entry->key));
            ldmd_strlcpy(entry->value, value, sizeof(entry->value));
        }
    }
    
    fclose(fp);
    return ini;
}

static void ini_free(ini_file_t *ini) {
    if (ini) {
        free(ini->entries);
        free(ini);
    }
}

static const char *ini_get(ini_file_t *ini, const char *section, const char *key, 
                           const char *default_value) {
    for (int i = 0; i < ini->count; i++) {
        if (strcasecmp(ini->entries[i].section, section) == 0 &&
            strcasecmp(ini->entries[i].key, key) == 0) {
            return ini->entries[i].value;
        }
    }
    return default_value;
}

static int ini_get_int(ini_file_t *ini, const char *section, const char *key, int default_value) {
    const char *value = ini_get(ini, section, key, NULL);
    if (value) {
        return atoi(value);
    }
    return default_value;
}

static bool ini_get_bool(ini_file_t *ini, const char *section, const char *key, bool default_value) {
    const char *value = ini_get(ini, section, key, NULL);
    if (value) {
        if (strcasecmp(value, "true") == 0 || 
            strcasecmp(value, "yes") == 0 || 
            strcasecmp(value, "1") == 0) {
            return true;
        }
        if (strcasecmp(value, "false") == 0 || 
            strcasecmp(value, "no") == 0 || 
            strcasecmp(value, "0") == 0) {
            return false;
        }
    }
    return default_value;
}

ldmd_config_t *config_load(const char *path) {
    ini_file_t *ini = ini_parse(path);
    if (!ini) {
        return NULL;
    }
    
    ldmd_config_t *config = calloc(1, sizeof(ldmd_config_t));
    if (!config) {
        ini_free(ini);
        return NULL;
    }
    
    // Server settings
    ldmd_strlcpy(config->server_host, 
                 ini_get(ini, "server", "host", "0.0.0.0"),
                 sizeof(config->server_host));
    config->server_port = ini_get_int(ini, "server", "port", 8080);
    ldmd_strlcpy(config->web_root,
                 ini_get(ini, "server", "web_root", "web"),
                 sizeof(config->web_root));
    config->max_body_size = ini_get_int(ini, "server", "max_body_size", 10485760);
    
    // Database settings
    ldmd_strlcpy(config->db_path,
                 ini_get(ini, "database", "path", "data/localdocsmd.db"),
                 sizeof(config->db_path));
    
    // Security settings
    config->session_timeout = ini_get_int(ini, "security", "session_timeout", 86400);
    config->password_min_length = ini_get_int(ini, "security", "password_min_length", 8);
    config->max_login_attempts = ini_get_int(ini, "security", "max_login_attempts", 5);
    config->lockout_duration = ini_get_int(ini, "security", "lockout_duration", 300);
    ldmd_strlcpy(config->secret_key,
                 ini_get(ini, "security", "secret_key", "change_this_secret_key_in_production"),
                 sizeof(config->secret_key));
    
    // Admin settings
    config->localhost_admin = ini_get_bool(ini, "admin", "localhost_admin", true);
    ldmd_strlcpy(config->default_admin_username,
                 ini_get(ini, "admin", "default_username", "admin"),
                 sizeof(config->default_admin_username));
    ldmd_strlcpy(config->default_admin_email,
                 ini_get(ini, "admin", "default_email", "admin@localhost"),
                 sizeof(config->default_admin_email));
    
    // Storage settings
    ldmd_strlcpy(config->documents_path,
                 ini_get(ini, "storage", "documents_path", "data/documents"),
                 sizeof(config->documents_path));
    config->max_file_size = ini_get_int(ini, "storage", "max_file_size", 5242880);
    ldmd_strlcpy(config->allowed_extensions,
                 ini_get(ini, "storage", "allowed_extensions", ".md,.markdown,.txt,.json,.yaml,.yml"),
                 sizeof(config->allowed_extensions));
    
    ini_free(ini);
    
    LOG_INFO("Configuration loaded from: %s", path);
    LOG_INFO("Server: %s:%d", config->server_host, config->server_port);
    LOG_INFO("Database: %s", config->db_path);
    LOG_INFO("Documents: %s", config->documents_path);
    
    return config;
}

void config_free(ldmd_config_t *config) {
    free(config);
}
