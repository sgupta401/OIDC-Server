package com.intuit.oidc.service;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class UserDetailsConfig {

    @Bean
    public UserDetailsService userDetailsService() {

        UserDetails user1 = User.withDefaultPasswordEncoder()
                .username("sgupta1")
                .password("password")
                .roles("USER")
                .build();

        UserDetails user2 = User.withDefaultPasswordEncoder()
                .username("sgupta2")
                .password("password")
                .roles("ADMIN")
                .build();

        UserDetails user3 = User.withDefaultPasswordEncoder()
                .username("sgupta3")
                .password("password")
                .roles("USER", "MANAGER")
                .build();

        return new InMemoryUserDetailsManager(user1, user2, user3);
    }
}