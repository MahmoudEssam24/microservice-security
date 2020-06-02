package sa.com.me.security.model;

import java.util.Date;

import lombok.Data;
import sa.com.me.core.util.Constants;

@Data
public class AuthenticationResponse {
    private String accessToken;
    private String refreshToken;
    private String tokenType;
    private Date expiryDate;

    public AuthenticationResponse(String accessToken, String refreshToken, Long userId, Date expiryDate) {
        this.refreshToken = refreshToken;
        this.accessToken = accessToken;
        this.expiryDate = expiryDate;
        this.tokenType = Constants.TOKEN_TYPE;
    }
}