package sa.com.me.security.controller;

import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import sa.com.me.core.exception.NotAuthorizedException;
import sa.com.me.core.model.User;
import sa.com.me.security.client.UserClient;
import sa.com.me.security.model.AuthenticationResponse;
import sa.com.me.security.model.RefreshToken;
import sa.com.me.security.service.SecurityService;
import sa.com.me.security.service.UserService;
import sa.com.me.security.util.JwtTokenProvider;

@RestController
@Api(description = "Security APIs")
class SecurityController {

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    SecurityService securityService;

    @Autowired
    JwtTokenProvider tokenProvider;

    @Autowired
    UserService userService;

    @Autowired
    UserClient userClient;

    @PostMapping("/api/v1/public/auth")
    @ResponseStatus(HttpStatus.OK)
    @ApiOperation(value = "User authentication service", produces = "application/json")
    AuthenticationResponse authUser(@RequestBody User user) {
        User userAuthorized = securityService.authUser(user);
        Authentication authentication = userService.getUserAuthentication(userAuthorized);
        String accessToken = tokenProvider.generateToken(authentication, userAuthorized);
        String refreshToken = tokenProvider.generateRefreshToken(authentication, userAuthorized);
        AuthenticationResponse authResponse = new AuthenticationResponse(accessToken, refreshToken,
                userAuthorized.getId(), tokenProvider.getExpirationDateFromToken(accessToken));
        return authResponse;
    }

    @PostMapping("/api/v1/private/auth/refresh_token")
    @ResponseStatus(HttpStatus.OK)
    @ApiOperation(value = "User authentication service", produces = "application/json")
    AuthenticationResponse refreshToken(@RequestBody RefreshToken refreshToken,
            @RequestHeader("Authorization") String token) {

        String usernameRefreshToken = tokenProvider.getUsernameFromJWT(refreshToken.getRefreshToken());
        String usernameAccessToken = tokenProvider.getUsernameFromJWT(token);
        User userAuthorized = new User();
        if (usernameAccessToken.equals(usernameRefreshToken)
                && tokenProvider.getExpirationDateFromToken(refreshToken.getRefreshToken()).before(new Date())) {
            userAuthorized = userClient.getUserByEmail(usernameAccessToken);
            Authentication authentication = userService.getUserAuthentication(userAuthorized);
            String newAccessToken = tokenProvider.generateToken(authentication, userAuthorized);
            String newRefreshToken = tokenProvider.generateRefreshToken(authentication, userAuthorized);
            AuthenticationResponse authResponse = new AuthenticationResponse(newAccessToken, newRefreshToken,
                    userAuthorized.getId(), tokenProvider.getExpirationDateFromToken(newAccessToken));
            return authResponse;
        } else {
            throw new NotAuthorizedException("Invalid token", "401", "refreshToken");
        }
    }

}