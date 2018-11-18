package pl.mateuszwinnicki.boot.keycloak.rest;

import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PersonController {

    @GetMapping("/admin/echo")
    @Secured("ROLE_ADMIN")
    public String adminEcho() {
        return "Admin Echo";
    }

    @GetMapping("/user/echo")
    @Secured("ROLE_USER")
    public String userEcho() {
        return "User Echo";
    }

    @GetMapping("/guest/echo")
    public String guestEcho() {
        return "Guest Echo";
    }

}
