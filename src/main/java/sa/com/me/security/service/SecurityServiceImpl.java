package sa.com.me.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import sa.com.me.core.exception.NotAuthorizedException;
import sa.com.me.core.exception.NotFoundException;
import sa.com.me.core.model.User;
import sa.com.me.security.client.UserClient;

@Service
public class SecurityServiceImpl implements SecurityService {

    @Autowired
    private UserClient userClient;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public User authUser(User user) {
        User userRetrieved = userClient.getUserByEmail(user.getEmail());
        if (userRetrieved == null) {
            throw new NotFoundException("User not found", "404", "email");
        }
        if (passwordEncoder.matches(user.getPassword(), userRetrieved.getPassword())) {
            return userRetrieved;
        }
        throw new NotAuthorizedException("User not authorized", "401", "email");
    }

}