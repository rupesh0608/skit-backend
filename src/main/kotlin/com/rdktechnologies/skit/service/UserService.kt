package com.rdktechnologies.skit.service

import com.rdktechnologies.skit.entity.User
import com.rdktechnologies.skit.error.exceptions.UserNotFoundException
import com.rdktechnologies.skit.repository.UserRepository
import com.rdktechnologies.skit.service.auth.AuthUserDetails
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.stereotype.Service
@Service
class UserService:UserDetailsService {

    @Autowired
    private lateinit var userRepository: UserRepository

    override fun loadUserByUsername(username: String):UserDetails{
        val data=userRepository.findByEmail(username)
        if(data.isPresent) {
            val user: User = data.get()
            val authUserDetails= AuthUserDetails()
            authUserDetails.users=user
            return authUserDetails
        } else {
            throw UserNotFoundException("Invalid Credentials")
        }
    }


}