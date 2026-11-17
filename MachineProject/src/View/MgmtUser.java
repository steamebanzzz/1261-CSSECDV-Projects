
package View;

import Controller.SQLite;
import Controller.AppException;
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

    // ADD USER
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
            "Username:", usernameField,
            "Password:", passwordField,
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

        if (result != JOptionPane.OK_OPTION) {
            return;
        }

        String username = usernameField.getText();
        char[] password = passwordField.getPassword();
        char[] confirmation = confirmField.getPassword();

        try {
            int role = roleBox.getSelectedIndex() + 2;

            sqlite.addUser(
                    username,
                    password,
                    confirmation,
                    role
            );

            JOptionPane.showMessageDialog(
                    this,
                    "User account created successfully!",
                    "SUCCESS",
                    JOptionPane.INFORMATION_MESSAGE
            );

            init();

        } catch (IllegalArgumentException
                | AppException | SecurityException ex) {
            if (ex instanceof AppException
                    && ((AppException) ex).isFatal()) {
                return;
            }
            JOptionPane.showMessageDialog(
                    this,
                    ex.getMessage(),
                    "ACCOUNT CREATION FAILED",
                    JOptionPane.ERROR_MESSAGE
            );

        } finally {
            Arrays.fill(password, '\0');
            Arrays.fill(confirmation, '\0');
        }
    }

    // EDIT ROLE
    private void editRoleBtnActionPerformed(java.awt.event.ActionEvent evt) {

        if (table.getSelectedRow() >= 0) {
            int row = table.convertRowIndexToModel(
                    table.getSelectedRow());

            String[] options = {
                "1-DISABLED",
                "2-CLIENT",
                "3-STAFF",
                "4-MANAGER",
                "5-ADMIN"
            };

            int currentRole = (int) tableModel.getValueAt(row, 1);

            String result = (String) JOptionPane.showInputDialog(
                    this,
                    "USER: " + tableModel.getValueAt(row, 0),
                    "EDIT USER ROLE",
                    JOptionPane.QUESTION_MESSAGE,
                    null,
                    options,
                    options[currentRole - 1]);

            if (result != null) {
                try {
                    sqlite.updateUserRole(
                            tableModel.getValueAt(row, 0).toString(),
                            result.charAt(0) - '0');

                    init();

                } catch (IllegalArgumentException
                        | AppException | SecurityException ex) {
                    if (ex instanceof AppException
                            && ((AppException) ex).isFatal()) {
                        return;
                    }
                    JOptionPane.showMessageDialog(
                            this,
                            ex.getMessage(),
                            "User role could not be changed",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        }
    }

    // DELETE USER
    private void deleteBtnActionPerformed(java.awt.event.ActionEvent evt) {

        if (table.getSelectedRow() >= 0) {
            int row = table.convertRowIndexToModel(
                    table.getSelectedRow());

            String username = tableModel.getValueAt(row, 0).toString();

            int result = JOptionPane.showConfirmDialog(
                    this,
                    "Are you sure you want to delete " + username + "?",
                    "DELETE USER",
                    JOptionPane.YES_NO_OPTION);

            if (result == JOptionPane.YES_OPTION) {
                try {
                    sqlite.deleteUser(username);
                    init();

                } catch (IllegalArgumentException
                        | AppException | SecurityException ex) {
                    if (ex instanceof AppException
                            && ((AppException) ex).isFatal()) {
                        return;
                    }
                    JOptionPane.showMessageDialog(
                            this,
                            ex.getMessage(),
                            "User could not be deleted",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        }
    }

    // LOCK / UNLOCK USER
    private void lockBtnActionPerformed(java.awt.event.ActionEvent evt) {

        if (table.getSelectedRow() >= 0) {
            int row = table.convertRowIndexToModel(
                    table.getSelectedRow());

            String state = "lock";

            boolean currentlyLocked =
                    "1".equals(tableModel.getValueAt(row, 2) + "");

            if (currentlyLocked) {
                state = "unlock";
            }

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

                } catch (IllegalArgumentException
                        | AppException | SecurityException ex) {
                    if (ex instanceof AppException
                            && ((AppException) ex).isFatal()) {
                        return;
                    }
                    JOptionPane.showMessageDialog(
                            this,
                            ex.getMessage(),
                            "Account lock status could not be changed",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        }
    }

    // CHANGE PASSWORD
    private void chgpassBtnActionPerformed(java.awt.event.ActionEvent evt) {

        if (table.getSelectedRow() >= 0) {
            int row = table.convertRowIndexToModel(
                    table.getSelectedRow());

            JPasswordField currentPassword = new JPasswordField();
            JPasswordField password = new JPasswordField();
            JPasswordField confpass = new JPasswordField();

            designer(currentPassword, "CURRENT ADMIN PASSWORD");
            designer(password, "PASSWORD");
            designer(confpass, "CONFIRM PASSWORD");

            Object[] message = {
                "Enter Your Current Password:",
                currentPassword,
                "Enter New Password:",
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

            if (result == JOptionPane.OK_OPTION) {

                char[] current = currentPassword.getPassword();
                char[] entered = password.getPassword();
                char[] confirmation = confpass.getPassword();

                try {
                    sqlite.changeUserPassword(
                            tableModel.getValueAt(row, 0).toString(),
                            current, entered,
                            confirmation);

                    JOptionPane.showMessageDialog(
                            this,
                            "Password changed successfully.");

                } catch (IllegalArgumentException
                        | AppException | SecurityException ex) {
                    if (ex instanceof AppException
                            && ((AppException) ex).isFatal()) {
                        return;
                    }
                    JOptionPane.showMessageDialog(
                            this,
                            ex.getMessage(),
                            "Password change failed",
                            JOptionPane.ERROR_MESSAGE);

                } finally {
                    Arrays.fill(current, '\0');
                    Arrays.fill(entered, '\0');
                    Arrays.fill(confirmation, '\0');
                }
            }
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
