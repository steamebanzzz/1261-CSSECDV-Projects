package Controller;

import java.util.Arrays;

/**
 * SINGLE SOURCE OF TRUTH for authorization (role-based access control).
 *
 * Every controller operation (SQLite.authorize) and every UI panel/button
 * (Frame, *Home panels, Mgmt* panels) asks this class whether a role holds a
 * permission. Changing a row here changes both enforcement and visibility, so
 * the Access Control Matrix document maps 1:1 to this table.
 *
 * Policy notes (principle of least privilege, default deny):
 *  - Unregistered (no session) and Disabled (role 1) hold NO permissions.
 *  - Admin (5) manages users and security logs only; it is not a super admin,
 *    so it cannot manage products, view purchases, or create/modify admins.
 *  - Any role value outside 2-5 is denied (fail closed).
 */
public final class AccessControl {

    public static final int DISABLED = 1;
    public static final int CLIENT = 2;
    public static final int STAFF = 3;
    public static final int MANAGER = 4;
    public static final int ADMIN = 5;

    public enum Permission {
        // Home panels (users are routed only to the panel of their own role)
        VIEW_ADMIN_HOME("Admin Home", ADMIN),
        VIEW_MANAGER_HOME("Manager Home", MANAGER),
        VIEW_STAFF_HOME("Staff Home", STAFF),
        VIEW_CLIENT_HOME("Client Home", CLIENT),

        // Products
        VIEW_PRODUCTS("View product list", CLIENT, STAFF, MANAGER),
        PURCHASE_PRODUCT("Purchase product", CLIENT),
        ADD_PRODUCT("Add product", STAFF, MANAGER),
        EDIT_PRODUCT("Edit product", STAFF, MANAGER),
        DELETE_PRODUCT("Delete product", STAFF, MANAGER),

        // Purchase history
        VIEW_OWN_HISTORY("View/search own purchase history", CLIENT),
        VIEW_ALL_HISTORY("View/search purchase history of all users",
                MANAGER),

        // User management
        VIEW_USERS("View user accounts", ADMIN),
        ADD_USER("Create user account (roles 2-4)", ADMIN),
        EDIT_USER_ROLE("Change user role (roles 1-4)", ADMIN),
        LOCK_USER("Lock (disable) user account", ADMIN),
        UNLOCK_USER("Unlock (re-enable) user account", ADMIN),
        DELETE_USER("Delete user account", ADMIN),
        CHANGE_USER_PASSWORD("Change user password", ADMIN),

        // Security logs
        VIEW_LOGS("View security logs", ADMIN),
        ARCHIVE_LOGS("Archive (clear) security logs", ADMIN);

        private final String description;
        private final int[] roles;

        Permission(String description, int... roles) {
            this.description = description;
            this.roles = roles;
        }

        public String getDescription() {
            return description;
        }

        int[] roles() {
            return Arrays.copyOf(roles, roles.length);
        }
    }

    private AccessControl() {
    }

    /** Default deny: true only when the role is explicitly granted. */
    public static boolean isAllowed(int role, Permission permission) {
        if (permission == null || role < CLIENT || role > ADMIN) {
            return false;
        }
        for (int allowed : permission.roles) {
            if (allowed == role) {
                return true;
            }
        }
        return false;
    }

    /** The home panel permission for a role, or null for no valid role. */
    public static Permission homeFor(int role) {
        switch (role) {
            case ADMIN:
                return Permission.VIEW_ADMIN_HOME;
            case MANAGER:
                return Permission.VIEW_MANAGER_HOME;
            case STAFF:
                return Permission.VIEW_STAFF_HOME;
            case CLIENT:
                return Permission.VIEW_CLIENT_HOME;
            default:
                return null;
        }
    }

    /** Roles an administrator may assign when creating an account. */
    public static boolean isAssignableOnCreate(int role) {
        return role >= CLIENT && role <= MANAGER;
    }

    /** Roles an administrator may assign when editing an account. */
    public static boolean isAssignableOnEdit(int role) {
        return role >= DISABLED && role <= MANAGER;
    }
}
