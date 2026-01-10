package com.example.demo.service.implementation;

import com.example.demo.model.UserPrincipal;
import com.example.demo.model.Users;
import com.example.demo.repo.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.List;


//Database-la namma Users nu oru table vachirupom. Aana Spring Security-ku puriyura language UserDetails. Namma table-la irukura data-vah Spring-ku puriyura UserDetails format-ku maathi kudukka thaan intha class use aaguthu.
@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Users user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        Collection<GrantedAuthority> authorities =
                List.of(new SimpleGrantedAuthority(user.getRole()));
        //Namma table-la "ADMIN" nu irukura String-ah, Spring Security-ku puriyura GrantedAuthority type-ku mathurom. Itha vachu thaan Spring user-oda permissions-ah decide pannum.

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                authorities
        );
        //Ithu thaan final product. Database-la irunthu edutha username, password, and roles-ah vachu Spring Security-oda internal User object-ah create panni tharrom.
    }
}
