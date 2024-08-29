package andrevsc.java_api_security_web.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
// import org.springframework.security.access.prepost.PreAuthorize;

@RestController
public class WelcomeController {

    @GetMapping("/welcome/user")
    // @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public String welcomeUser() {
        return "Welcome, User!";
    }

    @GetMapping("/welcome/admin")
    // @PreAuthorize("hasRole('ADMIN')")
    public String welcomeAdmin() {
        return "Welcome, Admin!";
    }

    @GetMapping("/welcome/all")
    public String welcomeAll() {
        return "Welcome, Everyone!";
    }
}
