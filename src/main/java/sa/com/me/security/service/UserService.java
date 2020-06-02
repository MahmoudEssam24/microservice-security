package sa.com.me.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import sa.com.me.core.model.User;
import sa.com.me.security.util.CustomAuthenticationProvider;
import sa.com.me.security.util.CustomUserDetailsService;

@Service
public class UserService {

	@Autowired
	CustomAuthenticationProvider authenticationManager;

	@Autowired
	CustomUserDetailsService userDetailsService;

	public Authentication getUserAuthentication(User registeredUser) {
		return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(registeredUser.getEmail(), "",
				userDetailsService.getAuthorities(registeredUser.getRoles())));
	}

}
