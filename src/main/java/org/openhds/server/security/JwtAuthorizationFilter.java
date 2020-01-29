/**
 * @author Nick Littlefield
 */

package org.openhds.server.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.openhds.server.service.impl.UserServiceImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter{
    private SecurityProperties properties;
    private UserServiceImpl userServiceImpl;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager,
                                  final SecurityProperties properties, final UserServiceImpl userServiceImpl){
        super(authenticationManager);
        this.properties = properties;
        this.userServiceImpl = userServiceImpl;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
        throws IOException, ServletException {

        String header = req.getHeader(properties.getHeaderString());

        if(header == null || !header.startsWith(properties.getTokenPrefix() + " ")){
            chain.doFilter(req, res);
            return;
        }

        UsernamePasswordAuthenticationToken authentication = getAuthentication(req);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(req, res);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest req){
        String token = req.getHeader(properties.getHeaderString());
        if(token != null){
            // parse the token.
            String user = JWT.require(Algorithm.HMAC512(properties.getSecret().getBytes()))
                    .build()
                    .verify(token.replace(properties.getTokenPrefix() + " ", ""))
                    .getSubject();

            if(user != null){
                return new UsernamePasswordAuthenticationToken(user, null, this.userServiceImpl.loadUserAuthorities(user));
            }

            return null;
        }

        return null;
    }
}

