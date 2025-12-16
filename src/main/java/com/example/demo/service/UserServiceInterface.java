package com.example.demo.service;

import com.example.demo.model.Users;

import java.util.List;
import java.util.Map;

public interface UserServiceInterface {
    Users register(Users user);

    List<Users> getAll();


    Map<String, String> verify(Users user); // <-- changed from String to Map
}
