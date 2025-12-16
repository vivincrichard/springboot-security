package com.example.demo.controller;

import com.example.demo.model.Users;
import com.example.demo.service.implementation.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
public class UserController {

    @Autowired
    private UserService userService;



    @PostMapping("/register")
    public Users registerUser(@RequestBody  Users user) {
        return userService.register(user);
    }

    @GetMapping("/users")
    public List<Users> getAllUser() {
        return userService.getAll();
    }

//    @PostMapping("/login")
//    public String login(@RequestBody Users user){
//        return userService.verify(user);
//    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody Users user){
        Map<String, String> tokens = userService.verify(user);
        return ResponseEntity.ok(tokens);
    }

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, String>> refresh(@RequestBody Map<String, String> body){
        String refreshToken = body.get("refreshToken");
        Map<String, String> tokens = userService.refreshToken(refreshToken);
        return ResponseEntity.ok(tokens);
    }


    @GetMapping("/admin/dashboard")
    public String adminPage() {
        return "Admin access OK";
    }
    @GetMapping("/users/me")
    public String userDashboard() {
        return "User access OK";
    }

}
