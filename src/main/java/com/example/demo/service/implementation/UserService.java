package com.example.demo.service.implementation;


import com.example.demo.model.RefreshToken;
import com.example.demo.model.Users;
import com.example.demo.repo.RefreshTokenRepository;
import com.example.demo.repo.UserRepository;
import com.example.demo.service.UserServiceInterface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

//@Service
//public class UserService implements UserServiceInterface {
//
//    @Autowired
//    private UserRepository userRepository;
//
//    @Autowired
//    private AuthenticationManager authManager;
//
//    @Autowired
//    private JWTService jwtService;
//
//    private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
//
//    @Override
//    public Users register(Users user) {
//        user.setPassword(encoder.encode(user.getPassword()));
//
//        // Automatically assign default role
//        if (user.getRole() == null) {
//            user.setRole("ROLE_USER");
//        }
//        else {
//            // If user sends "ADMIN", convert to "ROLE_ADMIN"
//            user.setRole("ROLE_" + user.getRole().toUpperCase());
//        }
//
//        return userRepository.save(user);
//    }
//
//
//    @Override
//    public List<Users> getAll() {
//        return userRepository.findAll();
//    }
//
//    @Override
//    public String verify(Users user) {
//        Authentication authentication =
//                authManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword()));
//
//        if(authentication.isAuthenticated()) {
//            Users dbUser = userRepository.findByUsername(user.getUsername()).get();
//            return jwtService.generateToken(dbUser.getUsername(), dbUser.getRole());
//        }
//
//        return "failed";
//    }
//}

@Service
public class UserService implements UserServiceInterface {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuthenticationManager authManager;

    @Autowired
    private JWTService jwtService;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private BCryptPasswordEncoder encoder;

    @Override
    public Users register(Users user) {
        user.setPassword(encoder.encode(user.getPassword()));
        if (user.getRole() == null) user.setRole("ROLE_USER");
        else user.setRole("ROLE_" + user.getRole().toUpperCase());
        return userRepository.save(user);
    }

    @Override
    public List<Users> getAll() {
        return userRepository.findAll();
    }

//    @Override
//    public Map<String, String> verify(Users user) {
//        Authentication authentication =
//                authManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
//
//        if (authentication.isAuthenticated()) {
//            Users dbUser = userRepository.findByUsername(user.getUsername()).get();
//
//            String accessToken = jwtService.generateAccessToken(dbUser.getUsername(), dbUser.getRole());
//            String refreshTokenStr = jwtService.generateRefreshToken(dbUser.getUsername());
//
//            // Save refresh token in DB
//            RefreshToken refreshToken = new RefreshToken();
//            refreshToken.setToken(refreshTokenStr);
//            refreshToken.setUser(dbUser);
//            refreshToken.setExpiryDate(Instant.now().plusMillis(7 * 24 * 60 * 60 * 1000L));
//            refreshTokenRepository.save(refreshToken);
//
//            Map<String, String> tokens = new HashMap<>();
//            tokens.put("accessToken", accessToken);
//            tokens.put("refreshToken", refreshTokenStr);
//            return tokens;
//        }
//
//        throw new BadCredentialsException("Invalid credentials");
//    }


//    public Map<String, String> refreshToken(String refreshTokenStr) {
//        RefreshToken refreshToken = refreshTokenRepository.findByToken(refreshTokenStr)
//                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));
//
//        if (refreshToken.getExpiryDate().isBefore(Instant.now())) {
//            refreshTokenRepository.delete(refreshToken);
//            throw new RuntimeException("Refresh token expired, login again");
//        }
//
//        Users user = refreshToken.getUser();
//        String newAccessToken = jwtService.generateAccessToken(user.getUsername(), user.getRole());
//
//        Map<String, String> tokenMap = new HashMap<>();
//        tokenMap.put("accessToken", newAccessToken);
//        tokenMap.put("refreshToken", refreshTokenStr); // same refresh token
//        return tokenMap;
//    }

    @Override
    public Map<String, String> verify(Users user) {
        Authentication authentication =
                authManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));

        if (authentication.isAuthenticated()) {
            Users dbUser = userRepository.findByUsername(user.getUsername()).get();

            // Generate access token (JWT)
            String accessToken = jwtService.generateAccessToken(dbUser.getUsername(), dbUser.getRole());

            // Generate random UUID refresh token
            String refreshTokenStr = UUID.randomUUID().toString();

            // Save refresh token in DB
            RefreshToken refreshToken = new RefreshToken();
            refreshToken.setToken(refreshTokenStr);
            refreshToken.setUser(dbUser);
            refreshToken.setExpiryDate(Instant.now().plusMillis(7 * 24 * 60 * 60 * 1000L)); // 7 days
            refreshTokenRepository.save(refreshToken);

            Map<String, String> tokens = new HashMap<>();
            tokens.put("accessToken", accessToken);
            tokens.put("refreshToken", refreshTokenStr);
            return tokens;
        }

        throw new BadCredentialsException("Invalid credentials");
    }

    public Map<String, String> refreshToken(String refreshTokenStr) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(refreshTokenStr)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        if (refreshToken.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(refreshToken);
            throw new RuntimeException("Refresh token expired, login again");
        }

        Users user = refreshToken.getUser();
        String newAccessToken = jwtService.generateAccessToken(user.getUsername(), user.getRole());

        Map<String, String> tokenMap = new HashMap<>();
        tokenMap.put("accessToken", newAccessToken);
        tokenMap.put("refreshToken", refreshTokenStr); // same UUID token
        return tokenMap;
    }
}

