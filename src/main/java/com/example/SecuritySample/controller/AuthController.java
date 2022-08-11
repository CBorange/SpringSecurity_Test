package com.example.SecuritySample.controller;

import com.example.SecuritySample.dto.JwtRequestDto;
import com.example.SecuritySample.dto.JwtResponseDto;
import com.example.SecuritySample.dto.MemberSignupRequestDto;
import com.example.SecuritySample.service.AuthService;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;
    private ObjectMapper mapper = new ObjectMapper();

    public AuthController(AuthService authService){
        this.authService = authService;
    }

    @PostMapping(value = "login", produces = MediaType.APPLICATION_JSON_VALUE)
    public String login(@RequestBody JwtRequestDto request){
        try{
            JwtResponseDto response = authService.login(request);
            return response.getAccessToken();
        }catch (Exception e){
            return e.getMessage();
        }
    }

    @PostMapping(value = "signup", produces = MediaType.APPLICATION_JSON_VALUE)
    public String signup(@RequestBody MemberSignupRequestDto request){
        return authService.signup(request);
    }
}
