/**
 * @author Nick Littlefield
 */

package org.openhds.server.security;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.openhds.server.domain.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.openhds.server.service.impl.UserServiceImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private AuthenticationManager authManager;
    private SecurityProperties properties;
    private UserServiceImpl userServiceImpl;
    public JwtAuthenticationFilter(AuthenticationManager authenticationManager,
                                   final SecurityProperties securityProperties,
                                   final UserServiceImpl userServiceImpl){
        this.authManager = authenticationManager;
        this.properties = securityProperties;
        this.userServiceImpl = userServiceImpl;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res)
            throws AuthenticationException {
        try{
            User usr = new ObjectMapper().readValue(req.getInputStream(), User.class);
            return authManager.authenticate(new UsernamePasswordAuthenticationToken(usr.getUsername(),
                    usr.getPassword(), this.userServiceImpl.convertUserRoles(usr.getRoles())));
        } catch(IOException e){
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest req, HttpServletResponse res,
                                            FilterChain chain, Authentication auth){

        String token = JWT.create()
                .withSubject(((UserDetails) auth.getPrincipal()).getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + properties.getExpirationTime()))
                .sign(Algorithm.HMAC512(properties.getSecret().getBytes()));

        res.addHeader(properties.getHeaderString(), properties.getTokenPrefix() + " " + token);
    }
}
