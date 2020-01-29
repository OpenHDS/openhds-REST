package org.openhds.server.service.impl;

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
public class UserServiceImpl implements UserDetailsService {

	@Autowired
	UserRepository repository;
    

    private Collection<GrantedAuthority> convertAuthorities(Set<Role> roles) {
		Collection<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();

		for(Role role : roles) {
			authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getName()));

			if(role.getPrivileges().size() != 0) {
				for (Privilege priv : role.getPrivileges()) {
					authorities.add(new SimpleGrantedAuthority(priv.getPrivilege()));
				}
			}
		}

		System.out.println("Authorities: "  + authorities);
		
		return authorities;
	}

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = repository.findByUsername(username);
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), convertAuthorities(user.getRoles()));
    }

    public Collection<GrantedAuthority> loadUserAuthorities(String username) throws UsernameNotFoundException{
    	User user = this.repository.findByUsername(username);
		return this.convertAuthorities(user.getRoles());
	}

	public Collection<GrantedAuthority> convertUserRoles(Set<Role> roles) throws UsernameNotFoundException{
		return this.convertAuthorities(roles);
	}
}