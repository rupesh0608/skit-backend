package com.rdktechnologies.skit.security

import com.rdktechnologies.skit.service.UserService
import com.rdktechnologies.skit.utils.JWTFilter
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter


@Configuration
@EnableWebSecurity
class SecurityConfiguration: WebSecurityConfigurerAdapter() {

    @Autowired
    lateinit var userService: UserService

    @Autowired
    lateinit var jwtFilter: JWTFilter

    override fun configure(auth: AuthenticationManagerBuilder) {
        auth.userDetailsService(userService)
    }

   // @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Bean
    override fun authenticationManagerBean(): AuthenticationManager? {
        return super.authenticationManagerBean()
    }


    override fun configure(http: HttpSecurity) {
        http.csrf()
                .disable()
                .authorizeRequests()
                .antMatchers("/swagger-ui/**",
                        "/v3/api-docs",
                        "/v3/api-docs/**",
                        "/api/auth/user/forgot_password/otp/verify",
                        "/api/auth/user/forgot_password",
                        "/api/auth/user/facebook_login",
                        "/api/auth/verify/user_account",
                        "/api/auth/welcome",
                        "/api/auth/user/login",
                        "/api/auth/user/registration")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter::class.java)
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder? {
        return BCryptPasswordEncoder()
    }
}