package com.example.demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration  //இது ஒரு Spring configuration classனு சொல்றது.
@EnableWebSecurity  //Spring Security-ஐ enable பண்ணுது. Web security features activate ஆகும்.
public class SecurityConfig {

    @Autowired
    private UserDetailsService userDetailsService;  //User-ஓட details (username, password, roles) database-ல இருந்து load பண்ற service.

    @Autowired
    private JwtFilter jwtFilter;    //Custom JWT filter – JWT token validate பண்ணி user-ஐ authenticate பண்றது.

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())   //CSRF protection off பண்ணுது. JWT use பண்ணும்போது stateless ஆக இருக்குறதால CSRF தேவையில்லை (token header-ல வரும், cookie-ல இல்லை).
                .authorizeHttpRequests(request -> request
                        .requestMatchers("/register", "/login","/users","/refresh").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/users/**").hasAnyRole("USER", "ADMIN")
                        .anyRequest().authenticated()
                )
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )   //Session create பண்ண வேண்டாம். JWT token மட்டும் use பண்ணி stateless authentication (server session store பண்ணாது – scalable ஆ இருக்கும்).
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
// UsernamePasswordAuthenticationFilter -> இதோட job: /login endpoint-க்கு POST request வந்தா, username & password எடுத்து authenticate பண்ணி session create பண்ணும் (traditional form login-க்கு).
// JwtFilter -> இதோட job: ஒவ்வொரு request-க்கும் Authorization header-ல Bearer JWT token இருக்கானு check பண்ணும். Token valid ஆ இருந்தா, user-ஐ authenticate பண்ணி SecurityContext-ல set பண்ணும் (அடுத்த filters-க்கு user யாருனு தெரியும்).
// addFilterBefore() ->நம்ம JwtFilter-ஐ, default UsernamePasswordAuthenticationFilter-க்கு முன்னாடி filter chain-ல insert பண்றது.
        return http.build();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public AuthenticationProvider authenticationProvider(BCryptPasswordEncoder encoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(); //"Dao"னு சொல்றதால Data Access Object → database-ல இருந்து user details எடுக்கும்.
        provider.setPasswordEncoder(encoder);   //User கொடுத்த plain password-ஐ hash பண்ணும்,Database-ல இருக்குற hashed password-ஓட compare பண்ணும், Match ஆகும்னா OK, இல்லேனா fail.
        provider.setUserDetailsService(userDetailsService); //இது database-ல இருந்து user details எடுக்கும் (userDetailsService use பண்ணி).
        return provider;
    }

    //authenticationManager → நம்ம இந்த bean (DaoAuthenticationProvider)-ஐ call பண்ணும்.
    //Provider:
    //userDetailsService → DB-ல "raj" இருக்கானு பார்க்கும் → hashed password "$2a$12$abc..." + roles ["USER"] எடுக்கும்.
    //encoder → "raj123"ஐ hash பண்ணி DB hashed-ஓட compare பண்ணும்.
    //Match → success → JWT token generate.

    // AuthenticationManager talks to the AuthenticationProvider
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    //AuthenticationManager ஒரு boss மாதிரி – இது தான் actual-ஆ “யாரு login பண்ணுறான்? சரியா?”னு decide பண்ணும்.
    //ஆனா இது தானா check பண்ணாது.
    //மேல இருக்குற AuthenticationProvider-கிட்ட கேக்கும்:
    //“டேய் provider, இந்த username & password சரியா?”
    //Provider “ஆமா சரி”னு சொன்னா, Manager success-ஆ JWT token generate பண்ணி தரும்.


}
