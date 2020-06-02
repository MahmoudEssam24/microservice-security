package sa.com.me.security.service;

import sa.com.me.core.model.User;

public interface SecurityService {
    public User authUser(User user);
}