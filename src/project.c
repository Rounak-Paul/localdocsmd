#include "project.h"
#include "workspace.h"
#include "auth.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

ldmd_error_t project_create(ldmd_database_t *db, ldmd_config_t *config,
                            int64_t workspace_id, const char *name,
                            const char *description, int64_t created_by,
                            ldmd_project_t *project_out) {
    ldmd_project_t project;
    memset(&project, 0, sizeof(project));
    
    auth_generate_uuid(project.uuid);
    project.workspace_id = workspace_id;
    ldmd_strlcpy(project.name, name, LDMD_MAX_NAME);
    if (description) {
        ldmd_strlcpy(project.description, description, LDMD_MAX_DESCRIPTION);
    }
    project.created_by = created_by;
    
    ldmd_error_t err = db_project_create(db, &project);
    if (err != LDMD_OK) {
        return err;
    }
    
    // Create project directory
    ldmd_workspace_t workspace;
    err = db_workspace_get_by_id(db, workspace_id, &workspace);
    if (err != LDMD_OK) {
        db_project_delete(db, project.id);
        return err;
    }
    
    char path[LDMD_MAX_PATH];
    project_get_path(config, &workspace, &project, path, sizeof(path));
    err = utils_mkdir_p(path);
    if (err != LDMD_OK) {
        db_project_delete(db, project.id);
        return err;
    }
    
    if (project_out) {
        *project_out = project;
    }
    
    LOG_INFO("Project created: %s (uuid: %s)", name, project.uuid);
    return LDMD_OK;
}

ldmd_error_t project_update(ldmd_database_t *db, ldmd_project_t *project) {
    return db_project_update(db, project);
}

ldmd_error_t project_delete(ldmd_database_t *db, ldmd_config_t *config, int64_t project_id) {
    ldmd_project_t project;
    ldmd_error_t err = db_project_get_by_id(db, project_id, &project);
    if (err != LDMD_OK) {
        return err;
    }
    
    ldmd_workspace_t workspace;
    err = db_workspace_get_by_id(db, project.workspace_id, &workspace);
    if (err != LDMD_OK) {
        return err;
    }
    
    // Delete project directory
    char path[LDMD_MAX_PATH];
    project_get_path(config, &workspace, &project, path, sizeof(path));
    utils_rmdir_r(path);
    
    // Delete from database (cascades to documents)
    return db_project_delete(db, project_id);
}

ldmd_error_t project_get(ldmd_database_t *db, int64_t id, ldmd_project_t *project_out) {
    return db_project_get_by_id(db, id, project_out);
}

ldmd_error_t project_get_by_uuid(ldmd_database_t *db, const char *uuid,
                                 ldmd_project_t *project_out) {
    return db_project_get_by_uuid(db, uuid, project_out);
}

ldmd_error_t project_list(ldmd_database_t *db, int64_t workspace_id,
                          ldmd_project_t **projects_out, int *count_out) {
    return db_project_list(db, workspace_id, projects_out, count_out);
}

ldmd_error_t project_get_path(ldmd_config_t *config, const ldmd_workspace_t *workspace,
                              const ldmd_project_t *project, char *path_out, size_t path_size) {
    snprintf(path_out, path_size, "%s/%s/%s", 
             config->documents_path, workspace->uuid, project->uuid);
    return LDMD_OK;
}

// Project member operations (view permissions)
ldmd_error_t project_grant_view(ldmd_database_t *db, int64_t project_id,
                                int64_t user_id, int64_t granted_by) {
    ldmd_project_member_t member;
    memset(&member, 0, sizeof(member));
    member.project_id = project_id;
    member.user_id = user_id;
    member.can_view = true;
    member.granted_by = granted_by;
    
    return db_project_member_add(db, &member);
}

ldmd_error_t project_revoke_view(ldmd_database_t *db, int64_t project_id, int64_t user_id) {
    return db_project_member_remove(db, project_id, user_id);
}

ldmd_error_t project_can_view(ldmd_database_t *db, int64_t project_id,
                              int64_t user_id, bool *can_view) {
    return db_project_member_check(db, project_id, user_id, can_view);
}

ldmd_error_t project_list_members(ldmd_database_t *db, int64_t project_id,
                                  ldmd_project_member_t **members_out, int *count_out) {
    return db_project_member_list(db, project_id, members_out, count_out);
}

// Document operations
ldmd_error_t document_create(ldmd_database_t *db, ldmd_config_t *config,
                             int64_t project_id, const char *name,
                             const char *content, int64_t created_by,
                             ldmd_document_t *document_out) {
    ldmd_document_t doc;
    memset(&doc, 0, sizeof(doc));
    
    auth_generate_uuid(doc.uuid);
    doc.project_id = project_id;
    ldmd_strlcpy(doc.name, name, LDMD_MAX_NAME);
    doc.created_by = created_by;
    doc.updated_by = created_by;
    
    // Get project and workspace for path
    ldmd_project_t project;
    ldmd_error_t err = db_project_get_by_id(db, project_id, &project);
    if (err != LDMD_OK) {
        return err;
    }
    
    ldmd_workspace_t workspace;
    err = db_workspace_get_by_id(db, project.workspace_id, &workspace);
    if (err != LDMD_OK) {
        return err;
    }
    
    // Create document path
    snprintf(doc.path, sizeof(doc.path), "%s/%s/%s/%s.md",
             config->documents_path, workspace.uuid, project.uuid, doc.uuid);
    
    // Save content
    if (content) {
        err = utils_write_file(doc.path, content);
        if (err != LDMD_OK) {
            return err;
        }
    } else {
        // Create empty file
        err = utils_write_file(doc.path, "");
        if (err != LDMD_OK) {
            return err;
        }
    }
    
    err = db_document_create(db, &doc);
    if (err != LDMD_OK) {
        utils_delete_file(doc.path);
        return err;
    }
    
    if (document_out) {
        *document_out = doc;
    }
    
    LOG_INFO("Document created: %s (uuid: %s)", name, doc.uuid);
    return LDMD_OK;
}

ldmd_error_t document_update(ldmd_database_t *db, ldmd_document_t *document) {
    return db_document_update(db, document);
}

ldmd_error_t document_save_content(ldmd_config_t *config, const ldmd_document_t *document,
                                   const char *content) {
    (void)config;  // Unused - path is in document
    return utils_write_file(document->path, content ? content : "");
}

ldmd_error_t document_load_content(ldmd_config_t *config, const ldmd_document_t *document,
                                   char **content_out) {
    (void)config;
    return utils_read_file(document->path, content_out);
}

ldmd_error_t document_delete(ldmd_database_t *db, ldmd_config_t *config, int64_t document_id) {
    ldmd_document_t doc;
    ldmd_error_t err = db_document_get_by_id(db, document_id, &doc);
    if (err != LDMD_OK) {
        return err;
    }
    
    // Delete file
    utils_delete_file(doc.path);
    
    // Delete from database
    return db_document_delete(db, document_id);
    
    (void)config;
}

ldmd_error_t document_get(ldmd_database_t *db, int64_t id, ldmd_document_t *document_out) {
    return db_document_get_by_id(db, id, document_out);
}

ldmd_error_t document_get_by_uuid(ldmd_database_t *db, const char *uuid,
                                  ldmd_document_t *document_out) {
    return db_document_get_by_uuid(db, uuid, document_out);
}

ldmd_error_t document_list(ldmd_database_t *db, int64_t project_id,
                           ldmd_document_t **documents_out, int *count_out) {
    return db_document_list(db, project_id, documents_out, count_out);
}
