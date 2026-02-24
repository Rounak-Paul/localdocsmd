#include "localdocsmd.h"
#include "config.h"
#include "database.h"
#include "server.h"
#include "auth.h"
#include "utils.h"
#include "mongoose.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>

static void print_usage(const char *prog) {
    fprintf(stderr, "LocalDocsMD - Documentation Workspace Host\n");
    fprintf(stderr, "Version %s\n\n", LDMD_VERSION_STRING);
    fprintf(stderr, "Usage: %s [options]\n\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -c, --config FILE   Configuration file (default: config.ini)\n");
    fprintf(stderr, "  -p, --port PORT     Server port (overrides config)\n");
    fprintf(stderr, "  -d, --debug         Enable debug logging\n");
    fprintf(stderr, "  -h, --help          Show this help message\n");
    fprintf(stderr, "  -v, --version       Show version information\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  %s                          # Start with default config\n", prog);
    fprintf(stderr, "  %s -c /etc/localdocsmd.ini  # Use custom config\n", prog);
    fprintf(stderr, "  %s -p 8000                  # Override port\n", prog);
    fprintf(stderr, "\n");
}

static void print_version(void) {
    printf("LocalDocsMD %s\n", LDMD_VERSION_STRING);
    printf("Documentation Workspace Host\n");
    printf("Built with: mongoose, sqlite3, md4c\n");
}

int main(int argc, char *argv[]) {
    const char *config_path = "config.ini";
    int port_override = 0;
    bool debug = false;
    
    // Parse command line options
    static struct option long_options[] = {
        {"config",  required_argument, 0, 'c'},
        {"port",    required_argument, 0, 'p'},
        {"debug",   no_argument,       0, 'd'},
        {"help",    no_argument,       0, 'h'},
        {"version", no_argument,       0, 'v'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "c:p:dhv", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                config_path = optarg;
                break;
            case 'p':
                port_override = atoi(optarg);
                break;
            case 'd':
                debug = true;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'v':
                print_version();
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // Set log level
    log_set_level(debug ? LOG_DEBUG : LOG_INFO);
    
    LOG_INFO("Starting LocalDocsMD %s", LDMD_VERSION_STRING);
    
    // Load configuration
    ldmd_config_t *config = config_load(config_path);
    if (!config) {
        LOG_ERROR("Failed to load configuration from: %s", config_path);
        LOG_INFO("Creating default configuration...");
        
        // Create data directory
        utils_mkdir_p("data");
        
        // Create default config
        config = calloc(1, sizeof(ldmd_config_t));
        ldmd_strlcpy(config->server_host, "0.0.0.0", sizeof(config->server_host));
        config->server_port = 8080;
        ldmd_strlcpy(config->web_root, "web", sizeof(config->web_root));
        config->max_body_size = 10485760;
        ldmd_strlcpy(config->db_path, "data/localdocsmd.db", sizeof(config->db_path));
        config->session_timeout = 86400;
        config->password_min_length = 8;
        config->max_login_attempts = 5;
        config->lockout_duration = 300;
        ldmd_strlcpy(config->secret_key, "change_this_secret", sizeof(config->secret_key));
        ldmd_strlcpy(config->default_admin_username, "admin", sizeof(config->default_admin_username));
        ldmd_strlcpy(config->default_admin_email, "admin@localhost", sizeof(config->default_admin_email));
        ldmd_strlcpy(config->documents_path, "data/documents", sizeof(config->documents_path));
        config->max_file_size = 5242880;
        ldmd_strlcpy(config->allowed_extensions, ".md,.markdown,.txt", sizeof(config->allowed_extensions));
        config->num_threads = 0; /* auto-detect */
    }
    
    // Apply port override
    if (port_override > 0) {
        config->server_port = port_override;
    }
    
    // Create directories
    utils_mkdir_p(config->documents_path);
    
    // Initialize database
    ldmd_database_t *db = db_init(config->db_path);
    if (!db) {
        LOG_ERROR("Failed to initialize database");
        config_free(config);
        return 1;
    }
    
    // Check for existing users
    int user_count = 0;
    db_user_count(db, &user_count);
    
    if (user_count == 0) {
        LOG_INFO("No users found, creating default admin...");
        ldmd_user_t admin;
        ldmd_error_t err = auth_create_user(db, config, 
                                            config->default_admin_username,
                                            config->default_admin_email,
                                            "admin",  // Default password
                                            ROLE_ADMIN, &admin);
        if (err == LDMD_OK) {
            // Admin must change password on first login
            admin.status = USER_STATUS_ACTIVE;
            admin.password_change_pending = true;
            db_user_update(db, &admin);
            LOG_INFO("Created admin user: %s (password: admin)", config->default_admin_username);
            LOG_WARN("*** Default credentials: admin / admin ***");
            LOG_WARN("*** You will be required to change the password on first login ***");
        } else {
            LOG_ERROR("Failed to create admin user");
        }
    }
    
    // Create server
    ldmd_server_t *server = server_create(config, db);
    if (!server) {
        LOG_ERROR("Failed to create server");
        db_close(db);
        config_free(config);
        return 1;
    }
    
    // Set mongoose log level (suppress debug output unless -d flag)
    mg_log_set(debug ? MG_LL_DEBUG : MG_LL_ERROR);
    
    // Start server
    if (server_start(server) != LDMD_OK) {
        LOG_ERROR("Failed to start server");
        server_free(server);
        db_close(db);
        config_free(config);
        return 1;
    }
    
    LOG_INFO("==============================================");
    LOG_INFO("LocalDocsMD is now running!");
    LOG_INFO("Web interface: http://%s:%d", 
             strcmp(config->server_host, "0.0.0.0") == 0 ? "localhost" : config->server_host,
             config->server_port);
    LOG_INFO("==============================================");
    
    // Run server (blocks until stopped)
    server_run(server);
    
    // Cleanup
    LOG_INFO("Shutting down...");
    server_free(server);
    db_close(db);
    config_free(config);
    
    LOG_INFO("Goodbye!");
    return 0;
}
