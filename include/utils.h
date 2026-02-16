#ifndef UTILS_H
#define UTILS_H

#include "localdocsmd.h"
#include <stdarg.h>

// Logging levels
typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARN = 2,
    LOG_ERROR = 3
} log_level_t;

/**
 * Set log level
 * @param level Minimum level to log
 */
void log_set_level(log_level_t level);

/**
 * Log message
 * @param level Log level
 * @param fmt Format string
 * @param ... Arguments
 */
void log_msg(log_level_t level, const char *fmt, ...);

// Convenience macros
#define LOG_DEBUG(...) log_msg(LOG_DEBUG, __VA_ARGS__)
#define LOG_INFO(...) log_msg(LOG_INFO, __VA_ARGS__)
#define LOG_WARN(...) log_msg(LOG_WARN, __VA_ARGS__)
#define LOG_ERROR(...) log_msg(LOG_ERROR, __VA_ARGS__)

/**
 * Create directory recursively
 * @param path Directory path
 * @return LDMD_OK or error code
 */
ldmd_error_t utils_mkdir_p(const char *path);

/**
 * Check if file exists
 * @param path File path
 * @return true if exists
 */
bool utils_file_exists(const char *path);

/**
 * Check if path is directory
 * @param path Path
 * @return true if directory
 */
bool utils_is_directory(const char *path);

/**
 * Read file to string
 * @param path File path
 * @param content_out Output content (caller frees)
 * @return LDMD_OK or error code
 */
ldmd_error_t utils_read_file(const char *path, char **content_out);

/**
 * Write string to file
 * @param path File path
 * @param content Content to write
 * @return LDMD_OK or error code
 */
ldmd_error_t utils_write_file(const char *path, const char *content);

/**
 * Delete file
 * @param path File path
 * @return LDMD_OK or error code
 */
ldmd_error_t utils_delete_file(const char *path);

/**
 * Delete directory recursively
 * @param path Directory path
 * @return LDMD_OK or error code
 */
ldmd_error_t utils_rmdir_r(const char *path);

/**
 * Get file extension
 * @param path File path
 * @return Extension (including dot) or empty string
 */
const char *utils_get_extension(const char *path);

/**
 * Check if extension is allowed
 * @param ext Extension
 * @param allowed_list Comma-separated list of allowed extensions
 * @return true if allowed
 */
bool utils_extension_allowed(const char *ext, const char *allowed_list);

/**
 * Get current timestamp
 * @return Unix timestamp
 */
time_t utils_now(void);

/**
 * Format timestamp
 * @param ts Timestamp
 * @param buf Output buffer
 * @param size Buffer size
 * @return buf
 */
char *utils_format_time(time_t ts, char *buf, size_t size);

/**
 * URL encode string
 * @param str Input string
 * @param encoded_out Output encoded string (caller frees)
 * @return LDMD_OK or error code
 */
ldmd_error_t utils_url_encode(const char *str, char **encoded_out);

/**
 * URL decode string
 * @param str Input string
 * @param decoded_out Output decoded string (caller frees)
 * @return LDMD_OK or error code
 */
ldmd_error_t utils_url_decode(const char *str, char **decoded_out);

/**
 * Trim whitespace from string (in place)
 * @param str String to trim
 * @return Pointer to trimmed string
 */
char *utils_trim(char *str);

/**
 * Duplicate string
 * @param str String to duplicate
 * @return Duplicated string (caller frees)
 */
char *utils_strdup(const char *str);

/**
 * Safe string format
 * @param buf Output buffer
 * @param size Buffer size
 * @param fmt Format string
 * @param ... Arguments
 * @return Number of characters written (excluding null)
 */
int utils_snprintf(char *buf, size_t size, const char *fmt, ...);

#endif // UTILS_H
