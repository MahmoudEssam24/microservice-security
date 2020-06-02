package sa.com.me.security.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import sa.com.me.core.model.User;

@Service
@FeignClient(name = "user-service")
public interface UserClient {
    @GetMapping(value = "/internal/api/v1/private/users/{email}")
    public User getUserByEmail(@PathVariable("email") String email);
}