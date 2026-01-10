package com.example.demo.config;


import com.example.demo.service.implementation.CustomUserDetailsService;
import com.example.demo.service.implementation.JWTService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

//Request ulla varum pothu, antha token-ah check panni, "Ivaru namma aalu thaan, ivaru Admin/User" nu permission kudukkura velai ithu thaan.
@Component  //@Component: Itha oru Spring bean-ah register pannuthu, appo thaan SecurityConfig-la namma @Autowired panna mudiyum.
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private JWTService jwtService;  //Token-la irunthu username, roles-ah edukkavum, token expiry-ah check pannavum intha utility service help pannuthu.

    //Spring Boot-la irukkura ella Beans (objects) -ayum maintain panra oru periya "Store Room" thaan intha ApplicationContext.
    //Spring app start aagum pothu, @Service, @Component, @Repository nu namma potrukura ella classes-ayum object-ah create panni intha ApplicationContext ulla thaan vachurukkum.
    //Namma normal-ah @Autowired use panni object-ah eduppom. Aana sila nerangal-la namma manual-ah "Enaku intha object-ah ippo kudu" nu keka vendi varum. Athuku thaan intha context use aaguthu.
    //Intha JwtFilter oru low-level filter. Sila samayam Spring-oda dependency injection cycle-la CustomUserDetailsService munnadiye inject aagama poga vaaipu irukku (Circular Dependency issue thavirkka).
    //So, "Safe-ah" irukattum nu, Spring-oda "Store Room" (ApplicationContext) kitta poyi, "Anna, antha CustomUserDetailsService bean-ah mattum ippo konjam eduthu kudungalen" nu manual-ah kekurom.
    @Autowired
    ApplicationContext context;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

//          HttpServletRequest request (The Courier)
//               Ithu thaan Client (Frontend) kitta irunthu vara Letter mathiri.
//               Enna irukkum?: Request URL, Headers (Authorization Token irukkurathu inga thaan), Body, ipidi user anuppuna ellam details-um ithula thaan irukkum.
//               Namma code-la enna panrom?: request.getHeader("Authorization") nu pottu, antha token-ah ithula irunthu thaan edukkirom.
//          HttpServletResponse response (The Reply)
//              Ithu namma user-ku thirumba anuppa pora Response Sheet.
//              Enna irukkum?: Status codes (200 OK, 401 Unauthorized), Response Body, Headers.
//              Namma enna pannalam?: Oru vellai, token thappa irunthalo illa user-ku access illanalum, intha response object-ah vachu namma "Stop! You are not allowed" nu error message anupalaam.
//         FilterChain filterChain (The Pipeline)
//              Ithu thaan romba mukkiyam. Spring Security-la oru filter mattum irukkathu, neraiya filters வரிசையா (chain) irukkum.
//              Enna panrathu?: Intha filter-oda velai mudinjathukku apram, "Sari, adutha filter-ku po" nu request-ah thalli vidurathu thaan ithoda velai.
//              Kadaisi line: filterChain.doFilter(request, response); — Intha line-ah nee podalana, request un filter-oda appadiye ninnudum, Controller-ku pogaathu.

        String authHeader = request.getHeader("Authorization");
        String token = null;
        String username = null;

        if(authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
            username = jwtService.extractUsername(token);
        }

        // validate the bearer token

        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            //Spring Security-la SecurityContextHolder-ngurathu oru box mathiri. Oru user once login pannitta, antha box-la avaroda details (Authentication object) store aagidum.
            UserDetails userDetails = context.getBean(CustomUserDetailsService.class).loadUserByUsername(username);
            if (jwtService.validateToken(token, userDetails)) {

                String role = jwtService.extractRole(token);
                GrantedAuthority authority = new SimpleGrantedAuthority(role);
//                Spring Security-kku "Role" nu sonna puriyathu. Athuku therinjathellam "Authority" (Adhavathu intha person-ku enna panna urimai irukku?) nu thaan paakum.
//                Role (Namma kitta irukkurathu): Oru String value (Example: "ROLE_ADMIN" or "ROLE_USER").
//                GrantedAuthority (Spring-ku venadiyathu): Ithu oru Interface. Spring Security-la ulla yarukkum ithu vazhiya thaan permission kudukka mudiyum.
//                SimpleGrantedAuthority: Intha interface-oda oru implementation class thaan ithu. Oru simple String-ah Spring purinjikira mathiri oru "Permission Ticket"-ah mathi tharum.
//                new SimpleGrantedAuthority(role) moolama antha String-ah Spring Security-ku puriyura oru object-ah mathurom.

                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, List.of(authority));
//                UsernamePasswordAuthenticationToken -> User-oda details matrum avangaloda Roles-ah (Permissions) onna sethu, Spring Security-ku puriyura mathiri namma kudukura "Verified Identity Card" thaan intha UsernamePasswordAuthenticationToken.Itha vachu thaan Spring "Ivaru login pannittaaru" nu fix aagum.
//                userDetails (Yaaru ivaru?): Database-la irunthu edutha user details. Ithu thaan antha card-la irukura "Photo" mathiri.
//                null (Password enge?): Namma thaan munnadiye JWT token-ah check pannittome! So, password-ah intha idathula thirumba kudukka thevai illa. Athanala null nu vachikurom.
//                List.of(authority) (Ivaruku enna permission?): Ivaru ADMIN-ah? illa USER-ah? nu Spring-ku solrom. Itha vachu thaan Spring adutha gate-la ivara ulla vidalaama nu mudivu pannum.

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//                Intha line user-oda identity card-la (authToken) avaru entha idathula irunthu (IP address) request anupunaaru-ngura extra information-ah ottura velaiya pannuthu.
//                Intha request-ah anupunathu entha IP Address? Avanga entha Browser/Device (Session ID) use panraanga? nu ellathayum intha line edukkum.
//                buildDetails(request): Intha request-ah anupunathu entha IP Address? Avanga entha Browser/Device (Session ID) use panraanga? nu ellathayum intha line edukkum.
                // REQUIRED LINE — without this your roles will NEVER work

                SecurityContextHolder.getContext().setAuthentication(authToken);
//                SecurityContextHolder -> Ithu oru periya box mathiri. Intha box-la thaan "Ippo yaaru login panni ulla irukka?" ngura details store aagi irukkum.
            }

        }
        filterChain.doFilter(request,response);
//        Namma token-ah check panni, user-ah SecurityContextHolder-la set pannittom.Ippo namma request-ah next filter-ku anuppalana, request Controller-kku (un API code-ku) pogave pogaathu.
    }
}
