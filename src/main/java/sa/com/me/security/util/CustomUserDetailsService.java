package sa.com.me.security.util;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import sa.com.me.core.model.Role;
import sa.com.me.core.model.User;
import sa.com.me.security.client.UserClient;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    
    @Autowired
    UserClient userClient;

    public Collection<? extends GrantedAuthority> getAuthorities(Collection<Role> roles) {
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>(roles.size());

        for (Role role : roles)
            authorities.add(new SimpleGrantedAuthority("" + role.getName()));

        return authorities;
    }
    
    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Let people login with either username
        User user = userClient.getUserByEmail(username);
        return UserPrincipal.create(user);
    }
}