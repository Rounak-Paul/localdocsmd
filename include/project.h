#ifndef PROJECT_H
#define PROJECT_H

#include "localdocsmd.h"
#include "database.h"
#include "config.h"

/**
 * Create a new project
 * @param db Database handle
 * @param config Configuration
 * @param workspace_id Workspace ID
 * @param name Project name
 * @param description Description
 * @param created_by Creator user ID
 * @param project_out Output project
 * @return LDMD_OK or error code
 */
ldmd_error_t project_create(ldmd_database_t *db, ldmd_config_t *config,
                            int64_t workspace_id, const char *name,
                            const char *description, int64_t created_by,
                            ldmd_project_t *project_out);

/**
 * Update project
 * @param db Database handle
 * @param project Project to update
 * @return LDMD_OK or error code
 */
ldmd_error_t project_update(ldmd_database_t *db, ldmd_project_t *project);

/**
 * Delete project and all contents
 * @param db Database handle
 * @param config Configuration
 * @param project_id Project ID
 * @return LDMD_OK or error code
 */
ldmd_error_t project_delete(ldmd_database_t *db, ldmd_config_t *config, int64_t project_id);

/**
 * Get project by ID
 * @param db Database handle
 * @param id Project ID
 * @param project_out Output project
 * @return LDMD_OK or error code
 */
ldmd_error_t project_get(ldmd_database_t *db, int64_t id, ldmd_project_t *project_out);

/**
 * Get project by UUID
 * @param db Database handle
 * @param uuid Project UUID
 * @param project_out Output project
 * @return LDMD_OK or error code
 */
ldmd_error_t project_get_by_uuid(ldmd_database_t *db, const char *uuid,
                                 ldmd_project_t *project_out);

/**
 * List projects in workspace
 * @param db Database handle
 * @param workspace_id Workspace ID
 * @param projects_out Output array (caller frees)
 * @param count_out Output count
 * @return LDMD_OK or error code
 */
ldmd_error_t project_list(ldmd_database_t *db, int64_t workspace_id,
                          ldmd_project_t **projects_out, int *count_out);

/**
 * Get project directory path
 * @param config Configuration
 * @param workspace Workspace
 * @param project Project
 * @param path_out Output path buffer
 * @param path_size Path buffer size
 * @return LDMD_OK or error code
 */
ldmd_error_t project_get_path(ldmd_config_t *config, const ldmd_workspace_t *workspace,
                              const ldmd_project_t *project, char *path_out, size_t path_size);

// Document operations within projects

/**
 * Create a new document
 * @param db Database handle
 * @param config Configuration
 * @param project_id Project ID
 * @param name Document name
 * @param content Initial content
 * @param created_by Creator user ID
 * @param document_out Output document
 * @return LDMD_OK or error code
 */
ldmd_error_t document_create(ldmd_database_t *db, ldmd_config_t *config,
                             int64_t project_id, const char *name,
                             const char *content, int64_t created_by,
                             ldmd_document_t *document_out);

/**
 * Update document metadata
 * @param db Database handle
 * @param document Document to update
 * @return LDMD_OK or error code
 */
ldmd_error_t document_update(ldmd_database_t *db, ldmd_document_t *document);

/**
 * Save document content
 * @param config Configuration
 * @param document Document
 * @param content Content to save
 * @return LDMD_OK or error code
 */
ldmd_error_t document_save_content(ldmd_config_t *config, const ldmd_document_t *document,
                                   const char *content);

/**
 * Load document content
 * @param config Configuration
 * @param document Document
 * @param content_out Output content (caller frees)
 * @return LDMD_OK or error code
 */
ldmd_error_t document_load_content(ldmd_config_t *config, const ldmd_document_t *document,
                                   char **content_out);

/**
 * Delete document
 * @param db Database handle
 * @param config Configuration
 * @param document_id Document ID
 * @return LDMD_OK or error code
 */
ldmd_error_t document_delete(ldmd_database_t *db, ldmd_config_t *config, int64_t document_id);

/**
 * Get document by ID
 * @param db Database handle
 * @param id Document ID
 * @param document_out Output document
 * @return LDMD_OK or error code
 */
ldmd_error_t document_get(ldmd_database_t *db, int64_t id, ldmd_document_t *document_out);

/**
 * Get document by UUID
 * @param db Database handle
 * @param uuid Document UUID
 * @param document_out Output document
 * @return LDMD_OK or error code
 */
ldmd_error_t document_get_by_uuid(ldmd_database_t *db, const char *uuid,
                                  ldmd_document_t *document_out);

/**
 * List documents in project
 * @param db Database handle
 * @param project_id Project ID
 * @param documents_out Output array (caller frees)
 * @param count_out Output count
 * @return LDMD_OK or error code
 */
ldmd_error_t document_list(ldmd_database_t *db, int64_t project_id,
                           ldmd_document_t **documents_out, int *count_out);

#endif // PROJECT_H
