package com.rdktechnologies.skit.service.auth

import com.rdktechnologies.skit.dto.ChangePwdDto1
import com.rdktechnologies.skit.dto.UserDto
import org.springframework.http.ResponseEntity
import java.security.Principal

interface IAuthService {

    fun register(user: UserDto):ResponseEntity<Any>
    fun verifyAccount(key: String):ResponseEntity<Any>
    fun forgotPassword(email:String):ResponseEntity<Any>
    fun emailLogin(email:String,password:String):ResponseEntity<Any>
    fun facebookLogin(principal: Principal):ResponseEntity<Any>
    fun verifyOTPForForgotPassword(changePwdDto: ChangePwdDto1):ResponseEntity<Any>
}