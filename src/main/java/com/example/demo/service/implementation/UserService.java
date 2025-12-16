package com.example.demo.service.implementation;


import com.example.demo.model.Users;
import com.example.demo.repo.UserRepository;
import com.example.demo.service.UserServiceInterface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService implements UserServiceInterface {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuthenticationManager authManager;

    @Autowired
    private JWTService jwtService;

    private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);

    @Override
    public Users register(Users user) {
        user.setPassword(encoder.encode(user.getPassword()));

        // Automatically assign default role
        if (user.getRole() == null) {
            user.setRole("ROLE_USER");
        }
        else {
            // If user sends "ADMIN", convert to "ROLE_ADMIN"
            user.setRole("ROLE_" + user.getRole().toUpperCase());
        }

        return userRepository.save(user);
    }


    @Override
    public List<Users> getAll() {
        return userRepository.findAll();
    }

    @Override
    public String verify(Users user) {
        Authentication authentication =
                authManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword()));

        if(authentication.isAuthenticated()) {
            Users dbUser = userRepository.findByUsername(user.getUsername()).get();
            return jwtService.generateToken(dbUser.getUsername(), dbUser.getRole());
        }

        return "failed";
    }
}

