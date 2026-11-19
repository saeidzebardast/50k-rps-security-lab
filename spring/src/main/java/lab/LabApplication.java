package lab;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * One codebase, two profiles:
 *   SPRING_PROFILES_ACTIVE=vulnerable  -> application-vulnerable.properties
 *   SPRING_PROFILES_ACTIVE=hardened    -> application-hardened.properties + BodyLimitFilter
 */
@SpringBootApplication
public class LabApplication {
    public static void main(String[] args) {
        SpringApplication.run(LabApplication.class, args);
    }
}
