package com.rdktechnologies.skit.controller.app


import com.rdktechnologies.skit.model.dto.app.*
import com.rdktechnologies.skit.service.app.auth.IAuthService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import javax.validation.Valid




@RestController
@RequestMapping("/api/app/auth/")
class AuthController {

    @Autowired
    private lateinit var authService : IAuthService

    @PostMapping("/signup")
    fun signup(@RequestBody(required=true) @Valid signupDto: SignupDto):ResponseEntity<Any>{
    return authService.signup(signupDto)
    }
    @PostMapping("/login")
    fun login(@RequestBody(required=true) @Valid loginDto: LoginDto):ResponseEntity<Any>{
        return authService.login(loginDto)
    }
    @PostMapping("/forgot_password")
    fun forgotPassword(@RequestBody(required=true) @Valid forgotPasswordDto: ForgotPasswordDto):ResponseEntity<Any>{
        return authService.forgotPassword(forgotPasswordDto)
    }
    @PostMapping("/reset_password")
    fun resetPassword(@RequestBody(required=true) @Valid resetPasswordDto: ResetPasswordDto):ResponseEntity<Any>{
        return authService.resetPassword(resetPasswordDto)
    }
    @PostMapping("/facebook_login")
    fun facebookLogin(@RequestBody(required=true) @Valid socialLoginDto: SocialLoginDto):ResponseEntity<Any>{
        return authService.facebookLogin(socialLoginDto)
    }
    @PostMapping("/google_login")
    fun googleLogin(@RequestBody(required=true) @Valid socialLoginDto: SocialLoginDto):ResponseEntity<Any>{
        return authService.googleLogin(socialLoginDto)
    }

}