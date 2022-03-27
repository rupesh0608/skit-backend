package com.rdktechnologies.skit.controller


import com.rdktechnologies.skit.dto.ChangePwdDto1
import com.rdktechnologies.skit.dto.EmailDto
import com.rdktechnologies.skit.dto.LoginDto
import com.rdktechnologies.skit.dto.UserDto
import com.rdktechnologies.skit.service.auth.IAuthService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import java.security.Principal
import javax.validation.Valid




@RestController
@RequestMapping("/api/auth/")
class AuthController {

    @Autowired
    private lateinit var authService : IAuthService

    @PostMapping("/user/registration")
    fun register(@RequestBody(required = true) @Valid user: UserDto): ResponseEntity<Any> {
        return authService.register(user)
    }
    @GetMapping("/verify/user_account")
    fun verifyAccount(@RequestParam(value = "key") key: String): ResponseEntity<Any> {
        return authService.verifyAccount(key)
    }
    @PostMapping("user/forgot_password")
    fun forgotPassword(@RequestBody(required = true) @Valid emailDto: EmailDto): ResponseEntity<Any> {
        return authService.forgotPassword(emailDto.email)
    }
    @PostMapping("user/forgot_password/verify/otp")
    fun verifyForgotPasswordOTP(@RequestBody(required = true) @Valid changePwdDto: ChangePwdDto1): ResponseEntity<Any> {
        return authService.verifyOTPForForgotPassword(changePwdDto)
    }

    @PostMapping("user/login")
    fun login(@RequestBody(required = true) @Valid loginDto: LoginDto): ResponseEntity<Any> {
        return authService.emailLogin(loginDto.email,loginDto.password)
    }
    @GetMapping("user/facebook_login")
    fun facebookLogin(principal: Principal): ResponseEntity<Any> {
        return authService.facebookLogin(principal)
    }

}