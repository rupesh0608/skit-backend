package com.rdktechnologies.skit.service.app.auth

import com.rdktechnologies.skit.model.dto.app.*
import org.springframework.http.ResponseEntity

interface IAuthService {
    fun signup(signupDto: SignupDto):ResponseEntity<Any>
    fun login(loginDto: LoginDto):ResponseEntity<Any>
    fun resetPassword(resetPasswordDto: ResetPasswordDto):ResponseEntity<Any>
    fun forgotPassword(forgotPasswordDto: ForgotPasswordDto):ResponseEntity<Any>
    fun googleLogin(socialLoginDto: SocialLoginDto):ResponseEntity<Any>
    fun facebookLogin(socialLoginDto: SocialLoginDto):ResponseEntity<Any>
}