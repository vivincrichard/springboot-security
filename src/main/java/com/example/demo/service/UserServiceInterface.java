package com.example.demo.service;

import com.example.demo.model.Users;

import java.util.List;

public interface UserServiceInterface {
    Users register(Users user);

    List<Users> getAll();


    String verify(Users user);
}
