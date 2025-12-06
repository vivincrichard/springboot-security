package com.example.demo.controller;

import com.example.demo.model.Users;
import com.example.demo.service.implementation.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

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

    @PostMapping("/login")
    public String login(@RequestBody Users user){
        return userService.verify(user);
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
