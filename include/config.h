#ifndef CONFIG_H
#define CONFIG_H

#include "localdocsmd.h"

// Configuration structure
struct ldmd_config {
    // Server settings
    char server_host[256];
    int server_port;
    char web_root[LDMD_MAX_PATH];
    size_t max_body_size;
    
    // Database settings
    char db_path[LDMD_MAX_PATH];
    
    // Security settings
    int session_timeout;
    int password_min_length;
    int max_login_attempts;
    int lockout_duration;
    char secret_key[256];
    
    // Admin settings
    char default_admin_username[LDMD_MAX_USERNAME];
    char default_admin_email[LDMD_MAX_EMAIL];
    
    // Storage settings
    char documents_path[LDMD_MAX_PATH];
    size_t max_file_size;
    char allowed_extensions[512];

    // Threading
    int num_threads;   /* 0 = auto (# CPU cores), 1 = single-threaded, N = N workers */
};

/**
 * Load configuration from file
 * @param path Path to configuration file
 * @return Configuration structure or NULL on error
 */
ldmd_config_t *config_load(const char *path);

/**
 * Free configuration
 * @param config Configuration to free
 */
void config_free(ldmd_config_t *config);

/**
 * Get configuration value as string
 * @param config Configuration
 * @param section Section name
 * @param key Key name
 * @param default_value Default value if not found
 * @return Configuration value or default
 */
const char *config_get_string(ldmd_config_t *config, const char *section, 
                              const char *key, const char *default_value);

/**
 * Get configuration value as integer
 */
int config_get_int(ldmd_config_t *config, const char *section, 
                   const char *key, int default_value);

/**
 * Get configuration value as boolean
 */
bool config_get_bool(ldmd_config_t *config, const char *section, 
                     const char *key, bool default_value);

#endif // CONFIG_H
