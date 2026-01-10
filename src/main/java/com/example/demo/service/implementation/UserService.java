package com.example.demo.service.implementation;


import com.example.demo.model.RefreshToken;
import com.example.demo.model.Users;
import com.example.demo.repo.RefreshTokenRepository;
import com.example.demo.repo.UserRepository;
import com.example.demo.service.UserServiceInterface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

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

    @Override
    public Map<String, String> verify(Users user) {

        // 1️⃣ Validation check
        if (!StringUtils.hasText(user.getUsername())
                || !StringUtils.hasText(user.getPassword())) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Username and password required"
            );
        }

        // 2️⃣ DB lookup (username/email not found)
        Users dbUser = userRepository.findByUsername(user.getUsername())
                .orElseThrow(() ->
                        new ResponseStatusException(
                                HttpStatus.UNAUTHORIZED,
                                "Invalid credentials"
                        )
                );

        // 3️⃣ Password check
        if (!encoder.matches(user.getPassword(), dbUser.getPassword())) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Invalid credentials"
            );
        }

        // 4️⃣ Generate tokens
        String accessToken = jwtService.generateAccessToken(dbUser.getUsername(),dbUser.getRole());

        String refreshTokenStr = UUID.randomUUID().toString();

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(refreshTokenStr);
        refreshToken.setUser(dbUser);
        refreshToken.setExpiryDate(
                Instant.now().plusMillis(2 * 60 * 1000L)
        );
        refreshTokenRepository.save(refreshToken);

        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", accessToken);
        tokens.put("refreshToken", refreshTokenStr);

        return tokens;
    }


    public Map<String, String> refreshToken(String refreshTokenStr) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(refreshTokenStr)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid refresh token"));

        // Check expiry
        if (refreshToken.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(refreshToken);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh token expired, login again");
        }

        // Generate new access token
        Users user = refreshToken.getUser();
        String newAccessToken = jwtService.generateAccessToken(user.getUsername(), user.getRole());

        Map<String, String> tokenMap = new HashMap<>();
        tokenMap.put("accessToken", newAccessToken);
        tokenMap.put("refreshToken", refreshTokenStr); // same UUID token
        return tokenMap;
    }

}

