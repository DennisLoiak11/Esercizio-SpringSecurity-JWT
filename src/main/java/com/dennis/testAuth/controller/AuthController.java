package com.dennis.testAuth.controller;

import com.dennis.testAuth.model.Role;
import com.dennis.testAuth.model.User;
import com.dennis.testAuth.repository.UserRepository;
import com.dennis.testAuth.service.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public String register(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String password = body.get("password");

        if (userRepository.findByUsername(username).isPresent()) {
            return "Utente già esistente";
        }

        User user = User.builder()
                .username(username)
                .password(passwordEncoder.encode(password)) // password criptata
                .role(Role.USER)
                .build();

        userRepository.save(user);
        return "Registrazione avvenuta con successo!";
    }

    @PostMapping("/login")
    public String login(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String password = body.get("password");

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Utente non trovato"));

        return jwtService.generateToken(user.getUsername(), user.getRole());
    }
}
