package com.auth.service.Impl;

import com.auth.model.User;
import com.auth.repository.UserRepository;
import com.auth.model.UserDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    UserRepository userRepository;

    @Override
    @Transactional
    public org.springframework.security.core.userdetails.UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {

        //String username = s;
        User user = userRepository.findByUsername(s)
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + s));

        return UserDetails.build(user);
    }
}
