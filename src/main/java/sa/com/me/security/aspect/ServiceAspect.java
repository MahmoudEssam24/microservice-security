package sa.com.me.security.aspect;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.stereotype.Component;

@Component
@Aspect
@Slf4j
public class ServiceAspect {

    @AfterReturning(value = "execution(* sa.com.me.security.service..*(..))", returning = "result")
    public void logResult(JoinPoint joinPoint, Object result) {
        log.info("Method {} returned: {}", joinPoint.getStaticPart().getSignature().toString() ,result);
    } 

    @Before("execution(* sa.com.me.security.service.UserService.*(..))")
    public void logResult(JoinPoint joinPoint) {
        StringBuilder arguments = new StringBuilder();
        log.info("Method called: {}", joinPoint.getStaticPart().getSignature().toString());
        Object[] signatureArgs = joinPoint.getArgs();
        for (Object signatureArg : signatureArgs) {
            arguments.append(signatureArg);
        }
        log.info("Method arguments: {}", arguments);
    }
}
