package org.openhds.server.service;

import org.openhds.server.dao.UserRepository;
import org.openhds.server.domain.Privilege;
import org.openhds.server.domain.Role;
import org.openhds.server.domain.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Set;

@Service
public class UserService implements UserDetailsService {

	@Autowired
	UserRepository repository;
    
	private final String SPRING_ROLE = "ROLE_CLIENT";

    private Collection<GrantedAuthority> convertAuthorities(Set<Role> roles) {
		Collection<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();

		authorities.add(new SimpleGrantedAuthority(SPRING_ROLE));
		for(Role role : roles) {
			authorities.add(new SimpleGrantedAuthority(role.getName()));
		}
		
		return authorities;
	}

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = repository.findByUsername(username);
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), convertAuthorities(user.getRoles()));
    }
}