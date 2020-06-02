package sa.com.me.security.util;

import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import sa.com.me.core.model.User;
import sa.com.me.core.util.Constants;

@Component
public class JwtTokenProvider {

    @Value("${app.jwtSecret}")
    private String jwtSecret;

    @Value("${app.jwtExpirationInMs}")
    private long jwtExpirationInMs;

    @Value("${app.jwtAuthoritiesKey}")
    private String authoritiesKey;

    @Value("${app.jwtRefreshTokenExpirationInMs}")
    private long jwtRefreshTokenExpirationInMs;

    public String getUsernameFromJWT(String token) {
        Claims claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();

        return claims.getSubject();
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUsernameFromJWT(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    public String generateToken(Authentication authentication, User user) {
        Date now = new Date();
        Long expiry = null;        
        expiry = jwtExpirationInMs;
        Date expiryDate = new Date(now.getTime() + expiry);
        return generateJwtToken(authentication, user, expiryDate);
    }

    public String generateRefreshToken(Authentication authentication, User user) {
        Date now = new Date();
        Long refreshExpiry = null;
        refreshExpiry = jwtRefreshTokenExpirationInMs;
        Date expiryDate = new Date(now.getTime() + refreshExpiry);
        return generateJwtToken(authentication, user, expiryDate);
    }

    private String generateJwtToken(Authentication authentication, User user, Date expiryDate) {
        final String authorities = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        return Jwts.builder().setSubject(authentication.getName()).setId(user.getId() + "")
                .claim(authoritiesKey, authorities).signWith(SignatureAlgorithm.HS512, jwtSecret)
                .setIssuedAt(new Date(System.currentTimeMillis())).setExpiration(expiryDate).compact();
    }

    public UsernamePasswordAuthenticationToken getAuthentication(final String token, final Authentication existingAuth,
            final UserDetails userDetails) {

        final JwtParser jwtParser = Jwts.parser().setSigningKey(jwtSecret);
        final Jws<Claims> claimsJws = jwtParser.parseClaimsJws(token);
        final Claims claims = claimsJws.getBody();
        final Collection<? extends GrantedAuthority> authorities = Arrays
                .stream(claims.get(authoritiesKey).toString().split(",")).map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        return new UsernamePasswordAuthenticationToken(userDetails, "", authorities);
    }
}
