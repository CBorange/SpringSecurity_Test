package com.example.SecuritySample.controller;

import com.example.SecuritySample.service.AuthService;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AllArgsConstructor
public class HomeController {
    private final AuthService authService;

    @GetMapping("/dashboard")
    public String dashboard(){
        return "dashboard";
    }

    @GetMapping("/admin")
    public String admin(){
        return "admin";
    }
}
