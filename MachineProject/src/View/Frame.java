package View;

import Controller.AccessControl;
import Controller.AccessControl.Permission;
import Controller.Main;
import Model.LoginResult;
import java.awt.AWTEvent;
import java.awt.CardLayout;
import java.awt.Toolkit;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.WindowConstants;

public class Frame extends javax.swing.JFrame {

    public Frame() {
        initComponents();
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        Container = new javax.swing.JPanel();
        HomePnl = new javax.swing.JPanel();
        Content = new javax.swing.JPanel();
        Navigation = new javax.swing.JPanel();
        adminBtn = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();
        managerBtn = new javax.swing.JButton();
        staffBtn = new javax.swing.JButton();
        clientBtn = new javax.swing.JButton();
        logoutBtn = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setBackground(new java.awt.Color(153, 153, 153));
        setMinimumSize(new java.awt.Dimension(800, 450));

        HomePnl.setBackground(new java.awt.Color(102, 102, 102));
        HomePnl.setPreferredSize(new java.awt.Dimension(801, 500));

        javax.swing.GroupLayout ContentLayout = new javax.swing.GroupLayout(Content);
        Content.setLayout(ContentLayout);
        ContentLayout.setHorizontalGroup(
            ContentLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 544, Short.MAX_VALUE)
        );
        ContentLayout.setVerticalGroup(
            ContentLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 0, Short.MAX_VALUE)
        );

        Navigation.setBackground(new java.awt.Color(204, 204, 204));

        adminBtn.setBackground(new java.awt.Color(250, 250, 250));
        adminBtn.setFont(new java.awt.Font("Tahoma", 1, 18)); // NOI18N
        adminBtn.setText("Admin Home");
        adminBtn.setFocusable(false);
        adminBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                adminBtnActionPerformed(evt);
            }
        });

        jLabel1.setFont(new java.awt.Font("Tahoma", 1, 24)); // NOI18N
        jLabel1.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel1.setText("SECURITY Svcs");
        jLabel1.setToolTipText("");

        managerBtn.setBackground(new java.awt.Color(250, 250, 250));
        managerBtn.setFont(new java.awt.Font("Tahoma", 1, 18)); // NOI18N
        managerBtn.setText("Manager Home");
        managerBtn.setFocusable(false);
        managerBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                managerBtnActionPerformed(evt);
            }
        });

        staffBtn.setBackground(new java.awt.Color(250, 250, 250));
        staffBtn.setFont(new java.awt.Font("Tahoma", 1, 18)); // NOI18N
        staffBtn.setText("Staff Home");
        staffBtn.setFocusable(false);
        staffBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                staffBtnActionPerformed(evt);
            }
        });

        clientBtn.setBackground(new java.awt.Color(250, 250, 250));
        clientBtn.setFont(new java.awt.Font("Tahoma", 1, 18)); // NOI18N
        clientBtn.setText("Client Home");
        clientBtn.setFocusable(false);
        clientBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                clientBtnActionPerformed(evt);
            }
        });

        logoutBtn.setBackground(new java.awt.Color(250, 250, 250));
        logoutBtn.setFont(new java.awt.Font("Tahoma", 1, 18)); // NOI18N
        logoutBtn.setText("LOGOUT");
        logoutBtn.setFocusable(false);
        logoutBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                logoutBtnActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout NavigationLayout = new javax.swing.GroupLayout(Navigation);
        Navigation.setLayout(NavigationLayout);
        NavigationLayout.setHorizontalGroup(
            NavigationLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(NavigationLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(NavigationLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(adminBtn, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jLabel1, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 226, Short.MAX_VALUE)
                    .addComponent(managerBtn, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(staffBtn, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(clientBtn, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(logoutBtn, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );
        NavigationLayout.setVerticalGroup(
            NavigationLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(NavigationLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 46, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(adminBtn, javax.swing.GroupLayout.PREFERRED_SIZE, 50, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(managerBtn, javax.swing.GroupLayout.PREFERRED_SIZE, 50, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(staffBtn, javax.swing.GroupLayout.PREFERRED_SIZE, 50, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(clientBtn, javax.swing.GroupLayout.PREFERRED_SIZE, 50, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 139, Short.MAX_VALUE)
                .addComponent(logoutBtn, javax.swing.GroupLayout.PREFERRED_SIZE, 50, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );

        javax.swing.GroupLayout HomePnlLayout = new javax.swing.GroupLayout(HomePnl);
        HomePnl.setLayout(HomePnlLayout);
        HomePnlLayout.setHorizontalGroup(
            HomePnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, HomePnlLayout.createSequentialGroup()
                .addComponent(Navigation, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(Content, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        HomePnlLayout.setVerticalGroup(
            HomePnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(Content, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addComponent(Navigation, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );

        javax.swing.GroupLayout ContainerLayout = new javax.swing.GroupLayout(Container);
        Container.setLayout(ContainerLayout);
        ContainerLayout.setHorizontalGroup(
            ContainerLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 980, Short.MAX_VALUE)
            .addGroup(ContainerLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(HomePnl, javax.swing.GroupLayout.DEFAULT_SIZE, 980, Short.MAX_VALUE))
        );
        ContainerLayout.setVerticalGroup(
            ContainerLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 500, Short.MAX_VALUE)
            .addGroup(ContainerLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(HomePnl, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(Container, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(Container, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void adminBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_adminBtnActionPerformed
        showRoleDashboard(AccessControl.ADMIN, adminHomePnl, "adminHomePnl");
    }//GEN-LAST:event_adminBtnActionPerformed

    private void managerBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_managerBtnActionPerformed
        showRoleDashboard(AccessControl.MANAGER, managerHomePnl, "managerHomePnl");
    }//GEN-LAST:event_managerBtnActionPerformed

    private void staffBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_staffBtnActionPerformed
        showRoleDashboard(AccessControl.STAFF, staffHomePnl, "staffHomePnl");
    }//GEN-LAST:event_staffBtnActionPerformed

    private void clientBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_clientBtnActionPerformed
        showRoleDashboard(AccessControl.CLIENT, clientHomePnl, "clientHomePnl");
    }//GEN-LAST:event_clientBtnActionPerformed

    private void logoutBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_logoutBtnActionPerformed
        try {
            main.sqlite.logout();
        } catch (RuntimeException ex) {
            // The user is signed out below no matter what.
        } finally {
            showLogin();
        }
    }//GEN-LAST:event_logoutBtnActionPerformed

    /** Minutes of inactivity before the session is ended automatically. */
    private static final int IDLE_MINUTES = 5;

    public Main main;
    public Login loginPnl = new Login();
    public Register registerPnl = new Register();

    private AdminHome adminHomePnl = new AdminHome();
    private ManagerHome managerHomePnl = new ManagerHome();
    private StaffHome staffHomePnl = new StaffHome();
    private ClientHome clientHomePnl = new ClientHome();

    private CardLayout contentView = new CardLayout();
    private CardLayout frameView = new CardLayout();
    private int currentDashboardRole = 0;
    private Timer idleTimer;

    public void init(Main controller){
        this.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        this.setTitle("CSSECDV - SECURITY Svcs");
        this.setLocationRelativeTo(null);

        this.main = controller;
        UiGuard.install(this);
        main.sqlite.setFatalErrorHandler(
                () -> SwingUtilities.invokeLater(this::handleFatalError));
        loginPnl.frame = this;
        registerPnl.frame = this;
        setRoleNavigation(0);

        adminHomePnl.init(main.sqlite);
        clientHomePnl.init(main.sqlite);
        managerHomePnl.init(main.sqlite);
        staffHomePnl.init(main.sqlite);

        Container.setLayout(frameView);
        Container.add(loginPnl, "loginPnl");
        Container.add(registerPnl, "registerPnl");
        Container.add(HomePnl, "homePnl");
        frameView.show(Container, "loginPnl");

        Content.setLayout(contentView);
        Content.add(adminHomePnl, "adminHomePnl");
        Content.add(managerHomePnl, "managerHomePnl");
        Content.add(staffHomePnl, "staffHomePnl");
        Content.add(clientHomePnl, "clientHomePnl");

        // Closing the window ends the session and records the logout.
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent event) {
                try {
                    main.sqlite.logout();
                } catch (RuntimeException ex) {
                    // Exiting anyway.
                }
            }
        });
        startIdleMonitor();

        this.setVisible(true);
    }

    /** Session idle timeout: any key or mouse activity restarts it. */
    private void startIdleMonitor() {
        idleTimer = new Timer(IDLE_MINUTES * 60 * 1000, event -> onIdleTimeout());
        idleTimer.setRepeats(false);
        Toolkit.getDefaultToolkit().addAWTEventListener(event -> {
            if (idleTimer.isRunning()) {
                idleTimer.restart();
            }
        }, AWTEvent.KEY_EVENT_MASK | AWTEvent.MOUSE_EVENT_MASK
                | AWTEvent.MOUSE_MOTION_EVENT_MASK
                | AWTEvent.MOUSE_WHEEL_EVENT_MASK);
    }

    private void onIdleTimeout() {
        if (currentDashboardRole == 0) {
            return;
        }
        try {
            main.sqlite.expireSession(IDLE_MINUTES);
        } catch (RuntimeException ex) {
            main.sqlite.invalidateSession();
        }
        showLogin();
        JOptionPane.showMessageDialog(this,
                "Your session expired after " + IDLE_MINUTES
                + " minutes of inactivity. Please sign in again.",
                "Session expired", JOptionPane.INFORMATION_MESSAGE);
    }

    /** The single "safe, unprivileged state": the login screen. */
    private void showLogin() {
        if (idleTimer != null) {
            idleTimer.stop();
        }
        currentDashboardRole = 0;
        loginPnl.clearCredentials();
        registerPnl.clearCredentials();
        setRoleNavigation(0);
        frameView.show(Container, "loginPnl");
    }

    private void handleFatalError() {
        main.sqlite.invalidateSession();
        showLogin();
        JOptionPane.showMessageDialog(
                this,
                "A system error occurred. Please sign in again.",
                "Session ended",
                JOptionPane.ERROR_MESSAGE);
    }

    /** Fail-safe for unexpected errors (called by UiGuard). */
    void resetToLogin(String errorType) {
        try {
            if (main != null && main.sqlite != null) {
                main.sqlite.recordUnexpectedError(errorType);
                main.sqlite.invalidateSession();
            }
        } finally {
            showLogin();
        }
    }

    /**
     * Re-checks the session after a denied request: a signed-out or revoked
     * user goes to login; a user whose role changed goes to their own home.
     */
    void enforceSession() {
        int role = main.sqlite.getAuthenticatedRole();
        if (role == 0) {
            showLogin();
        } else if (role != currentDashboardRole) {
            mainNav();
        }
    }

    public void mainNav(){
        int role = main.sqlite.getAuthenticatedRole();
        if (AccessControl.homeFor(role) == null) {
            showLogin();
            return;
        }

        setRoleNavigation(role);
        frameView.show(Container, "homePnl");
        if (role == AccessControl.ADMIN) {
            showRoleDashboard(role, adminHomePnl, "adminHomePnl");
        } else if (role == AccessControl.MANAGER) {
            showRoleDashboard(role, managerHomePnl, "managerHomePnl");
        } else if (role == AccessControl.STAFF) {
            showRoleDashboard(role, staffHomePnl, "staffHomePnl");
        } else {
            showRoleDashboard(role, clientHomePnl, "clientHomePnl");
        }
        if (idleTimer != null) {
            idleTimer.restart();
        }
    }

    /** Navigation visibility comes from the central AccessControl policy. */
    private void setRoleNavigation(int role) {
        adminBtn.setVisible(
                AccessControl.isAllowed(role, Permission.VIEW_ADMIN_HOME));
        managerBtn.setVisible(
                AccessControl.isAllowed(role, Permission.VIEW_MANAGER_HOME));
        staffBtn.setVisible(
                AccessControl.isAllowed(role, Permission.VIEW_STAFF_HOME));
        clientBtn.setVisible(
                AccessControl.isAllowed(role, Permission.VIEW_CLIENT_HOME));
        logoutBtn.setVisible(AccessControl.homeFor(role) != null);
    }

    private void showRoleDashboard(
            int role, JPanel dashboard, String cardName) {
        Permission home = AccessControl.homeFor(role);
        // Every home-panel request is authorized (and violations logged).
        if (home == null
                || !main.sqlite.authorizeView(home, home.getDescription())) {
            enforceSession();
            return;
        }

        if (dashboard == adminHomePnl) {
            adminHomePnl.showPnl("home");
        } else if (dashboard == managerHomePnl) {
            managerHomePnl.showPnl("home");
        } else if (dashboard == staffHomePnl) {
            staffHomePnl.showPnl("home");
        } else if (dashboard == clientHomePnl) {
            clientHomePnl.showPnl("home");
        }
        currentDashboardRole = role;
        contentView.show(Content, cardName);
    }

    public void loginNav(){
        if (main != null && main.sqlite.getAuthenticatedRole() != 0) {
            mainNav();
            return;
        }
        showLogin();
    }

    public void registerNav(){
        if (main.sqlite.getAuthenticatedRole() != 0) {
            mainNav();
            return;
        }
        registerPnl.clearCredentials();
        frameView.show(Container, "registerPnl");
    }

    public LoginResult loginAction(String username, char[] password) {
        LoginResult result = main.sqlite.login(username, password);
        if (result.isSuccessful()) {
            mainNav();
        }
        return result;
    }

    public void registerAction(
            String username, char[] password, char[] confirmation) {
        main.sqlite.addUser(username, password, confirmation);
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JPanel Container;
    private javax.swing.JPanel Content;
    private javax.swing.JPanel HomePnl;
    private javax.swing.JPanel Navigation;
    private javax.swing.JButton adminBtn;
    private javax.swing.JButton clientBtn;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JButton logoutBtn;
    private javax.swing.JButton managerBtn;
    private javax.swing.JButton staffBtn;
    // End of variables declaration//GEN-END:variables
}
