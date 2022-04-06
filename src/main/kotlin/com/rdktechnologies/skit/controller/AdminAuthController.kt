package com.rdktechnologies.skit.controller


import com.rdktechnologies.skit.model.dto.app.*
import com.rdktechnologies.skit.service.auth.IAuthService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import javax.validation.Valid



@CrossOrigin(origins = ["http://localhost:4200"])
@RestController
@RequestMapping("/api/admin/auth/")
class AdminAuthController {

    @Autowired
    private lateinit var authService : IAuthService

    @PostMapping("/signup")
    fun createAccount(@RequestBody(required=true) @Valid signupDto: SignupDto):ResponseEntity<Any>{
    return authService.signup(signupDto,"admin_signup")
    }
    @PostMapping("/login")
    fun login(@RequestBody(required=true) @Valid loginDto: LoginDto):ResponseEntity<Any>{
        return authService.login(loginDto,"admin_login")
    }
}