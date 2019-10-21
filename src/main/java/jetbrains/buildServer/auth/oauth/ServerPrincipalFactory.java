package jetbrains.buildServer.auth.oauth;

import jetbrains.buildServer.groups.SUserGroup;
import jetbrains.buildServer.groups.UserGroupManager;
import jetbrains.buildServer.serverSide.auth.ServerPrincipal;
import jetbrains.buildServer.users.InvalidUsernameException;
import jetbrains.buildServer.users.SUser;
import jetbrains.buildServer.users.UserModel;
import org.apache.log4j.Logger;
import org.jetbrains.annotations.NotNull;

import java.util.Optional;


public class ServerPrincipalFactory {

    private static final Logger LOG = Logger.getLogger(ServerPrincipalFactory.class);

    @NotNull
    private final UserModel userModel;

    @NotNull
    private final UserGroupManager userGroupManager;

    public ServerPrincipalFactory(@NotNull UserModel userModel, @NotNull UserGroupManager userGroupManager) {
        this.userModel = userModel;
        this.userGroupManager = userGroupManager;
    }

    @NotNull
    public Optional<ServerPrincipal> getServerPrincipal(@NotNull final OAuthUser user, boolean allowCreatingNewUsersByLogin) {
        Optional<ServerPrincipal> existingPrincipal = findExistingPrincipal(user.getId());
        if (existingPrincipal.isPresent()) {
            LOG.info("Use existing user: " + user.getId());
            return existingPrincipal;
        } else if (allowCreatingNewUsersByLogin) {
            LOG.info("Creating user: " + user);
            SUser created = userModel.createUserAccount(PluginConstants.OAUTH_AUTH_SCHEME_NAME, user.getId());
            for(String group : user.getGroups()) {
                SUserGroup userGroup = userGroupManager.findUserGroupByName(group);
                if(userGroup != null) {
                    userGroup.addUser(created);
                }
            }
            created.setUserProperty(PluginConstants.ID_USER_PROPERTY_KEY, user.getId());
            created.updateUserAccount(user.getId(), user.getName(), user.getEmail());
            return Optional.of(new ServerPrincipal(PluginConstants.OAUTH_AUTH_SCHEME_NAME, user.getId()));
        } else {
            LOG.info("User: " + user + " could not be found and allowCreatingNewUsersByLogin is disabled");
            return existingPrincipal;
        }
    }

    @NotNull
    private Optional<ServerPrincipal> findExistingPrincipal(@NotNull final String userName) {
        try {
            final SUser user = userModel.findUserByUsername(userName, PluginConstants.ID_USER_PROPERTY_KEY);
            return Optional.ofNullable(user).map(u -> new ServerPrincipal(PluginConstants.OAUTH_AUTH_SCHEME_NAME, user.getUsername()));
        } catch (InvalidUsernameException e) {
            // ignore it
            return Optional.empty();
        }
    }
}
