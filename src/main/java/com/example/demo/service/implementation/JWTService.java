package com.example.demo.service.implementation;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

// new code
@Service
public class JWTService {

//    private final long accessTokenValidity = 15 * 60 * 1000; // 15 mins
//    private final long refreshTokenValidity = 7 * 24 * 60 * 60 * 1000; // 7 days

    private final long accessTokenValidity = 1 * 60 * 1000; // 1 minute
    private final long refreshTokenValidity = 2 * 60 * 1000; // 2 minutes

    private final String SECRET = "this-is-a-very-long-secret-key-1234567890"; // >=32 chars

    private Key getKey() {
        return Keys.hmacShaKeyFor(SECRET.getBytes());
    }
    // Generate access token
    public String generateAccessToken(String username, String role) {
        return Jwts.builder()
                .setSubject(username)   //JWT-la Subject (sub) nu oru field irukkum. Adhu dhaan andha token yarudhu nu sollum. Inga namma User-oda Username-ah set pandrom. Idhu dhaan token-oda identity.
                .claim("role", role)    //Claims-na "thagaval" (information). subject illama neenga extra-va enna information venum nalum claim-ah add pannikkalam. Inga namma user-oda Role (e.g., ADMIN, USER) ah add pandrom.
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + accessTokenValidity))
                .signWith(getKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // Extract username
    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    // Extract role
    public String extractRole(String token) {
        return extractAllClaims(token).get("role", String.class);
    }

    // Extract all claims
    //ippo andha token-ah thirandhu adhukulla enna irukku nu paakanumla? Adhuku dhaan indha method.
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
//    -> setSigningKey(getKey())
//          Idhu dhaan romba mukkiyamaana step. Token-ah pirikkurathuku munnadi, andha token valid-ah nu check panna namma Secret Key-ah kudukkirom.
//          Logic: Token create panna use panna adhe key-ah inga kudutha dhaan, parser-ala andha signature-ah verify panna mudiyum. Key match aagalana, ingaye Error (Exception) adichidum
//    -> .parseClaimsJws(token)
//          Namma kudukkura String token-ah eduthu, signature match aagudha nu check panni, adhukulla irukka Header, Payload, Signature-ah pirikkudhu.
//          Note: Oru vela token expired aayirundhalum, illana yaravadhu token-ah mathi irundhalum, indha line-la dhaan application "Invalid Token"-nu kandupidiikkum.

    // Validate token
    public boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extractAllClaims(token).getExpiration().before(new Date());
    }
}

