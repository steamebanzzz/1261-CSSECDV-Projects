
package View;

import Controller.SQLite;

import Model.User;
import java.util.ArrayList;
import java.util.Arrays;
import javax.swing.JComboBox;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableModel;

public class MgmtUser extends javax.swing.JPanel {

    public SQLite sqlite;
    public DefaultTableModel tableModel;

    public MgmtUser(SQLite sqlite) {
        initComponents();
        this.sqlite = sqlite;
        tableModel = (DefaultTableModel) table.getModel();
        table.getTableHeader().setFont(
                new java.awt.Font("SansSerif", java.awt.Font.BOLD, 14));
    }

    public void init() {
        tableModel.setRowCount(0);

        ArrayList<User> users = sqlite.getUsers();

        for (int nCtr = 0; nCtr < users.size(); nCtr++) {
            tableModel.addRow(new Object[]{
                users.get(nCtr).getUsername(),
                users.get(nCtr).getRole(),
                users.get(nCtr).getLocked()
            });
        }
    }

    public void designer(JTextField component, String text) {
        component.setSize(70, 600);
        component.setFont(new java.awt.Font("Tahoma", 0, 18));
        component.setBackground(new java.awt.Color(240, 240, 240));
        component.setHorizontalAlignment(
                javax.swing.JTextField.CENTER);
        component.setBorder(
                javax.swing.BorderFactory.createTitledBorder(
                        new javax.swing.border.LineBorder(
                                new java.awt.Color(0, 0, 0), 2, true),
                        text,
                        javax.swing.border.TitledBorder.CENTER,
                        javax.swing.border.TitledBorder.DEFAULT_POSITION,
                        new java.awt.Font("Tahoma", 0, 12)));
    }

    private void initComponents() {

        jScrollPane1 = new javax.swing.JScrollPane();
        table = new javax.swing.JTable();

        addUserBtn = new javax.swing.JButton();
        editRoleBtn = new javax.swing.JButton();
        deleteBtn = new javax.swing.JButton();
        lockBtn = new javax.swing.JButton();
        chgpassBtn = new javax.swing.JButton();

        table.setFont(new java.awt.Font("SansSerif", 0, 14));

        table.setModel(new javax.swing.table.DefaultTableModel(
                new Object[][]{},
                new String[]{
                    "Username", "Role", "Locked"
                }
        ) {
            boolean[] canEdit = new boolean[]{
                false, false, false
            };

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit[columnIndex];
            }
        });

        table.setRowHeight(24);
        table.getTableHeader().setReorderingAllowed(false);
        jScrollPane1.setViewportView(table);

        if (table.getColumnModel().getColumnCount() > 0) {
            table.getColumnModel().getColumn(0).setPreferredWidth(160);
            table.getColumnModel().getColumn(1).setPreferredWidth(100);
            table.getColumnModel().getColumn(2).setPreferredWidth(100);
        }

        addUserBtn.setBackground(java.awt.Color.WHITE);
        addUserBtn.setFont(new java.awt.Font("Tahoma", 1, 14));
        addUserBtn.setText("ADD USER");
        addUserBtn.addActionListener(evt -> addUserBtnActionPerformed(evt));

        editRoleBtn.setBackground(java.awt.Color.WHITE);
        editRoleBtn.setFont(new java.awt.Font("Tahoma", 1, 14));
        editRoleBtn.setText("EDIT ROLE");
        editRoleBtn.addActionListener(evt -> editRoleBtnActionPerformed(evt));

        deleteBtn.setBackground(java.awt.Color.WHITE);
        deleteBtn.setFont(new java.awt.Font("Tahoma", 1, 14));
        deleteBtn.setText("DELETE");
        deleteBtn.addActionListener(evt -> deleteBtnActionPerformed(evt));

        lockBtn.setBackground(java.awt.Color.WHITE);
        lockBtn.setFont(new java.awt.Font("Tahoma", 1, 14));
        lockBtn.setText("LOCK/UNLOCK");
        lockBtn.addActionListener(evt -> lockBtnActionPerformed(evt));

        chgpassBtn.setBackground(java.awt.Color.WHITE);
        chgpassBtn.setFont(new java.awt.Font("Tahoma", 1, 14));
        chgpassBtn.setText("CHANGE PASS");
        chgpassBtn.addActionListener(evt -> chgpassBtnActionPerformed(evt));

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);

        layout.setHorizontalGroup(
                layout.createParallelGroup(
                        javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                                .addComponent(addUserBtn,
                                        javax.swing.GroupLayout.DEFAULT_SIZE,
                                        javax.swing.GroupLayout.DEFAULT_SIZE,
                                        Short.MAX_VALUE)
                                .addComponent(editRoleBtn,
                                        javax.swing.GroupLayout.DEFAULT_SIZE,
                                        javax.swing.GroupLayout.DEFAULT_SIZE,
                                        Short.MAX_VALUE)
                                .addComponent(deleteBtn,
                                        javax.swing.GroupLayout.DEFAULT_SIZE,
                                        javax.swing.GroupLayout.DEFAULT_SIZE,
                                        Short.MAX_VALUE)
                                .addComponent(lockBtn,
                                        javax.swing.GroupLayout.DEFAULT_SIZE,
                                        javax.swing.GroupLayout.DEFAULT_SIZE,
                                        Short.MAX_VALUE)
                                .addComponent(chgpassBtn,
                                        javax.swing.GroupLayout.DEFAULT_SIZE,
                                        javax.swing.GroupLayout.DEFAULT_SIZE,
                                        Short.MAX_VALUE))
                        .addComponent(jScrollPane1)
        );

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addComponent(jScrollPane1,
                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                222, Short.MAX_VALUE)
                        .addGroup(layout.createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING,
                                false)
                                .addComponent(addUserBtn,
                                        javax.swing.GroupLayout.PREFERRED_SIZE,
                                        41,
                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addComponent(editRoleBtn,
                                        javax.swing.GroupLayout.PREFERRED_SIZE,
                                        41,
                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addComponent(deleteBtn,
                                        javax.swing.GroupLayout.PREFERRED_SIZE,
                                        41,
                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addComponent(lockBtn,
                                        javax.swing.GroupLayout.PREFERRED_SIZE,
                                        41,
                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addComponent(chgpassBtn,
                                        javax.swing.GroupLayout.PREFERRED_SIZE,
                                        41,
                                        javax.swing.GroupLayout.PREFERRED_SIZE))
        );
    }

    // ADD USER (administrators may create Client, Staff or Manager only)
    private void addUserBtnActionPerformed(java.awt.event.ActionEvent evt) {

        JTextField usernameField = new JTextField();
        JPasswordField passwordField = new JPasswordField();
        JPasswordField confirmField = new JPasswordField();

        String[] roles = {
            "2 - CLIENT",
            "3 - STAFF",
            "4 - MANAGER"
        };

        JComboBox<String> roleBox = new JComboBox<>(roles);

        Object[] fields = {
            "Username (3-32 letters or digits):", usernameField,
            "Password (12-128 chars: A-Z, a-z, 0-9, symbol):", passwordField,
            "Confirm Password:", confirmField,
            "Role:", roleBox
        };

        int result = JOptionPane.showConfirmDialog(
                this,
                fields,
                "CREATE NEW USER",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE
        );

        char[] password = passwordField.getPassword();
        char[] confirmation = confirmField.getPassword();
        try {
            if (result != JOptionPane.OK_OPTION) {
                return;
            }
            int role = roleBox.getSelectedIndex() + 2;
            sqlite.addUser(usernameField.getText(), password, confirmation,
                    role);
            JOptionPane.showMessageDialog(
                    this,
                    "User account created successfully!",
                    "SUCCESS",
                    JOptionPane.INFORMATION_MESSAGE
            );
            init();
        } catch (RuntimeException ex) {
            UiGuard.handle(this, ex);
        } finally {
            Arrays.fill(password, '\0');
            Arrays.fill(confirmation, '\0');
            passwordField.setText("");
            confirmField.setText("");
        }
    }

    // EDIT ROLE (roles 1-4 only; requires the administrator's password)
    private void editRoleBtnActionPerformed(java.awt.event.ActionEvent evt) {

        if (table.getSelectedRow() < 0) {
            return;
        }
        int row = table.convertRowIndexToModel(table.getSelectedRow());
        String username = tableModel.getValueAt(row, 0).toString();

        String[] options = {
            "1-DISABLED",
            "2-CLIENT",
            "3-STAFF",
            "4-MANAGER"
        };
        int currentRole = (int) tableModel.getValueAt(row, 1);
        int selectedIndex = Math.min(Math.max(currentRole, 1), 4) - 1;

        JComboBox<String> roleBox = new JComboBox<>(options);
        roleBox.setSelectedIndex(selectedIndex);
        JPasswordField currentPassword = new JPasswordField();
        designer(currentPassword, "YOUR CURRENT PASSWORD");

        Object[] message = {
            "USER: " + username,
            "New role:", roleBox,
            "Re-enter your password to confirm:", currentPassword
        };

        int result = JOptionPane.showConfirmDialog(
                this, message, "EDIT USER ROLE",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        char[] current = currentPassword.getPassword();
        try {
            if (result != JOptionPane.OK_OPTION) {
                return;
            }
            sqlite.updateUserRole(
                    username, roleBox.getSelectedIndex() + 1, current);
            init();
        } catch (RuntimeException ex) {
            UiGuard.handle(this, ex);
            refreshQuietly();
        } finally {
            Arrays.fill(current, '\0');
            currentPassword.setText("");
        }
    }

    // DELETE USER (requires the administrator's password)
    private void deleteBtnActionPerformed(java.awt.event.ActionEvent evt) {

        if (table.getSelectedRow() < 0) {
            return;
        }
        int row = table.convertRowIndexToModel(table.getSelectedRow());
        String username = tableModel.getValueAt(row, 0).toString();

        JPasswordField currentPassword = new JPasswordField();
        designer(currentPassword, "YOUR CURRENT PASSWORD");
        Object[] message = {
            "Are you sure you want to delete " + username + "?",
            "Re-enter your password to confirm:", currentPassword
        };

        int result = JOptionPane.showConfirmDialog(
                this, message, "DELETE USER",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);

        char[] current = currentPassword.getPassword();
        try {
            if (result != JOptionPane.OK_OPTION) {
                return;
            }
            sqlite.deleteUser(username, current);
            init();
        } catch (RuntimeException ex) {
            UiGuard.handle(this, ex);
            refreshQuietly();
        } finally {
            Arrays.fill(current, '\0');
            currentPassword.setText("");
        }
    }

    // LOCK / UNLOCK USER
    private void lockBtnActionPerformed(java.awt.event.ActionEvent evt) {

        if (table.getSelectedRow() < 0) {
            return;
        }
        int row = table.convertRowIndexToModel(table.getSelectedRow());
        boolean currentlyLocked =
                "1".equals(tableModel.getValueAt(row, 2) + "");
        String state = currentlyLocked ? "unlock" : "lock";
        String username = tableModel.getValueAt(row, 0).toString();

        int result = JOptionPane.showConfirmDialog(
                this,
                "Are you sure you want to " + state + " " + username + "?",
                "LOCK/UNLOCK USER",
                JOptionPane.YES_NO_OPTION);

        if (result == JOptionPane.YES_OPTION) {
            try {
                sqlite.setUserLocked(username, !currentlyLocked);
                init();
            } catch (RuntimeException ex) {
                UiGuard.handle(this, ex);
                refreshQuietly();
            }
        }
    }

    // CHANGE PASSWORD (requires the administrator's password)
    private void chgpassBtnActionPerformed(java.awt.event.ActionEvent evt) {

        if (table.getSelectedRow() < 0) {
            return;
        }
        int row = table.convertRowIndexToModel(table.getSelectedRow());
        String username = tableModel.getValueAt(row, 0).toString();

        JPasswordField currentPassword = new JPasswordField();
        JPasswordField password = new JPasswordField();
        JPasswordField confpass = new JPasswordField();

        designer(currentPassword, "YOUR CURRENT PASSWORD");
        designer(password, "NEW PASSWORD");
        designer(confpass, "CONFIRM NEW PASSWORD");

        Object[] message = {
            "USER: " + username,
            "Re-enter your password to confirm:",
            currentPassword,
            "New password (12-128 chars: A-Z, a-z, 0-9, symbol):",
            password,
            confpass
        };

        int result = JOptionPane.showConfirmDialog(
                this,
                message,
                "CHANGE PASSWORD",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE,
                null);

        char[] current = currentPassword.getPassword();
        char[] entered = password.getPassword();
        char[] confirmation = confpass.getPassword();
        try {
            if (result != JOptionPane.OK_OPTION) {
                return;
            }
            sqlite.changeUserPassword(username, current, entered,
                    confirmation);
            JOptionPane.showMessageDialog(
                    this, "Password changed successfully.");
        } catch (RuntimeException ex) {
            UiGuard.handle(this, ex);
        } finally {
            Arrays.fill(current, '\0');
            Arrays.fill(entered, '\0');
            Arrays.fill(confirmation, '\0');
            currentPassword.setText("");
            password.setText("");
            confpass.setText("");
        }
    }

    /** Reloads the table after a failure, if the user is still allowed. */
    private void refreshQuietly() {
        if (isShowing() && sqlite.canAccess(
                Controller.AccessControl.Permission.VIEW_USERS)) {
            UiGuard.run(this, this::init);
        }
    }

    // COMPONENT DECLARATIONS
    private javax.swing.JButton addUserBtn;
    private javax.swing.JButton chgpassBtn;
    private javax.swing.JButton deleteBtn;
    private javax.swing.JButton editRoleBtn;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JButton lockBtn;
    private javax.swing.JTable table;
}
