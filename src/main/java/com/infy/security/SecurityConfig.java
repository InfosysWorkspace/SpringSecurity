package com.infy.security;

import antlr.BaseAST;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    //Authentication

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        auth.inMemoryAuthentication()
                .withUser("buhari")
                .password(passwordEncoder().encode("buhari123"))
                .roles("ADMIN")
                .and()
                .withUser("maryam")
                .password(passwordEncoder().encode("maryam123"))
                .roles("USER");
    }



    //Authorization

    @Override
    protected void configure(HttpSecurity http ) throws Exception{
        http.authorizeRequests()
                .antMatchers("/infybank/customers/**")
                .hasRole("ADMIN")
                .anyRequest().authenticated()
                .and().httpBasic();
        http.csrf().disable();
    }


    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
