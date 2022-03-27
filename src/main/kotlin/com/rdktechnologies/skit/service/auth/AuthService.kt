package com.rdktechnologies.skit.service.auth


import com.ongraph.daverick.recipie.social.app.constants.Permissions
import com.ongraph.daverick.recipie.social.app.constants.Roles
import com.rdktechnologies.skit.dto.ChangePwdDto1
import com.rdktechnologies.skit.dto.UserDto
import com.rdktechnologies.skit.dto.response.LoginResponse
import com.rdktechnologies.skit.dto.response.LoginUserData
import com.rdktechnologies.skit.dto.response.SimpleResponse
import com.rdktechnologies.skit.entity.*
import com.rdktechnologies.skit.error.exceptions.*
import com.rdktechnologies.skit.repository.*
import com.rdktechnologies.skit.service.UserService
import com.rdktechnologies.skit.utils.JWTUtility
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.ResponseEntity
import org.springframework.mail.javamail.JavaMailSender
import org.springframework.mail.javamail.MimeMessageHelper
import org.springframework.scheduling.annotation.Async
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.stereotype.Service
import org.thymeleaf.context.Context
import org.thymeleaf.spring5.SpringTemplateEngine
import java.nio.charset.StandardCharsets
import java.security.Principal
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.*
import javax.mail.internet.MimeMessage


@Service
class AuthService : IAuthService {
    @Autowired
    lateinit var jwtUtility: JWTUtility

    @Autowired
    lateinit var authenticationManager: AuthenticationManager

    @Autowired
    lateinit var userService: UserService

    @Autowired
    private lateinit var userRepository: UserRepository

    @Autowired
    private lateinit var tokenRepository: TokenRepository

    @Autowired
    private lateinit var otpRepository: OTPRepository

    @Autowired
    private lateinit var roleRepository: RoleRepository

    @Autowired
    private lateinit var privilegeRepository: PrivilegeRepository

    @Autowired
    private lateinit var emailSender: JavaMailSender

    @Autowired
    private lateinit var templateEngine: SpringTemplateEngine

    override fun register(user: UserDto): ResponseEntity<Any> {
        if(userRepository.findByEmail(user.email).isPresent) throw AlreadyExistException("The given email already exists.")

        val password = encodePassword(user.password, user.confirmPassword)

        val privilege = createPrivilegeIfNotFound(name = Permissions.READ_PRIVILEGE)

        val roles = createRoleIfNotFound(name = Roles.ROLE_USER, privileges = privilege)

        val userObj = User(firstName = user.firstName,
                lastName = user.lastName,
                email = user.email,
                password = password,
                isEnabled = false,
                isAccountNonExpired = true,
                isCredentialsNonExpired = true,
                isAccountNonLocked = true, roles = roles)

        val tokenObj = generateToken(userObj)
        val link = "?key=${tokenObj.token}"
        sendEmailVerification(userObj, link)
        tokenRepository.save(tokenObj)
        return ResponseEntity.ok(SimpleResponse(false, 200, "verification Link send to ${user.email}"))
    }

    override fun verifyAccount(key: String): ResponseEntity<Any> {
        val tokenObj: Optional<ConfirmationToken> = tokenRepository.findByToken(key)
        if (tokenObj.isPresent) {
            val data = tokenObj.get()
            if (isExpired(data.expiredAt)) throw MatchNotFoundException("token Expired..")
            validateEmailToken(data)
            return ResponseEntity.ok(SimpleResponse(false, 200, "Account Successfully Verified."))
        } else {
            throw MatchNotFoundException("Some thing went wrong")
        }

    }

    override fun forgotPassword(email: String): ResponseEntity<Any> {
        val userObj: Optional<User> = userRepository.findByEmail(email)
        if (userObj.isPresent) {
            val user = userObj.get()
            val otpObj = generateOTP(user)
            sendForgotPasswordEmail(user, otpObj)
            otpRepository.save(otpObj)
            return ResponseEntity.ok(SimpleResponse(false, 200, "OTP sent to $email"))
        } else {
            throw UserNotFoundException("The given email is not registered..")
        }
    }

    override fun emailLogin(email: String, password: String): ResponseEntity<Any> {
        val authentication: Authentication = authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken(
                        email,
                        password
                )
        )
        SecurityContextHolder.getContext().authentication = authentication
        val userDetails = authentication.principal as AuthUserDetails
        if (!authentication.isAuthenticated) throw UserNotFoundException("Invalid Credentials1")
        if (userDetails.users.isEnabled == false) throw UserNotVerifiedException("Please Verify your Account Before Login!!")
        val token = jwtUtility.generateToken(userDetails)
        val user = userDetails.users
        val res = LoginUserData(id = user.id,
                firstName = user.firstName,
                lastName = user.lastName,
                fullName = user.firstName + " " + user.lastName,
                email = user.email
        )
        return ResponseEntity.ok(LoginResponse(false, 200, "LoggedIn Successfully!!", token, res))
    }

    override fun facebookLogin(principal: Principal): ResponseEntity<Any> {
        val authDetails = (principal as OAuth2Authentication)
                .userAuthentication
                .details as OAuth2Authentication

        val firstName = authDetails.name
        return ResponseEntity.ok(firstName)
    }

    override fun verifyOTPForForgotPassword(changePwdDto: ChangePwdDto1): ResponseEntity<Any> {

        val data = userRepository.findByEmail(changePwdDto.email)
        if (data.isPresent) {
            val user = data.get()
            if(changePwdDto.otp.equals("")) throw IncorrectOTPException("OTP is required")
            val otpData = otpRepository.findByUser(user)
            if (otpData.isPresent) {
                val otpObj = otpData.get()
                val otp = otpObj.otp
                if (isExpired(otpObj.expiredAt)) {
                    throw IncorrectOTPException("OTP Expired")
                }
                if(otp!=otpObj.otp){
                    throw IncorrectOTPException("Incorrect OTP")
                }
                user.password = encodePassword(changePwdDto.newPassword, changePwdDto.confirmPassword)
                userRepository.save(user)
                return ResponseEntity.ok(SimpleResponse(false, 200, "password successfully changed"))
            } else {
                throw Exception("Something went wrong..")
            }
        } else {
            throw UserNotFoundException("The given email is not registered...")
        }
    }


    //helper functions
    fun sendEmailVerification(user: User, link: String) {
        val message: MimeMessage = emailSender.createMimeMessage()
        val helper = MimeMessageHelper(
                message,
                MimeMessageHelper.MULTIPART_MODE_MIXED_RELATED,
                StandardCharsets.UTF_8.name()
        )
        val context = Context()
        val mail = HashMap<String, Any>()
        mail["name"] = user.firstName as Any
        mail["link"] = "http://localhost:8080/api/auth/verify/user_account$link"
        context.setVariables(mail)
        val html: String = templateEngine.process("email_verification", context)
        helper.setTo(user.email!!)
        helper.setText(html, true)
        helper.setSubject("Email Verification")
        helper.setFrom("recipieapp1234@gmail.com")
        emailSender.send(message)
    }

    fun sendForgotPasswordEmail(user: User, otpObj: ConfirmationOTP) {
        val message: MimeMessage = emailSender.createMimeMessage()
        val helper = MimeMessageHelper(
                message,
                MimeMessageHelper.MULTIPART_MODE_MIXED_RELATED,
                StandardCharsets.UTF_8.name()
        )
        val context = Context()
        val mail = HashMap<String, Any>()
        mail["name"] = otpObj.otp as Any
        context.setVariables(mail)
        val html: String = templateEngine.process("email_verification", context)
        helper.setTo(user.email!!)
        helper.setText(html, true)
        helper.setSubject("OTP for Forgot Password")
        helper.setFrom("recipieapp1234@gmail.com")
        emailSender.send(message)
    }

    fun generateToken(user: User): ConfirmationToken {
        val token = UUID.randomUUID().toString()
        val createdAt = Instant.now()
        val expiredAt = Instant.now().plus(30, ChronoUnit.MINUTES)
        return ConfirmationToken(users = user, token = token, createdAt = createdAt, expiredAt = expiredAt)
    }

    fun generateOTP(user: User): ConfirmationOTP {
        val rnd = Random()
        val otp = rnd.nextInt(999999)
        val createdAt = Instant.now()
        val expiredAt = Instant.now().plus(30, ChronoUnit.MINUTES)
        return ConfirmationOTP(user = user, otp = otp.toLong(), createdAt = createdAt, expiredAt = expiredAt)
    }

    fun encodePassword(password: String, confirmPassword: String): String {
        if (password != confirmPassword) throw MatchNotFoundException("password and confirmPassword must be the same.")
        return BCryptPasswordEncoder().encode(password)
    }

    @Async
    fun validateEmailToken(tokenObj: ConfirmationToken) {
        val user = tokenObj.users
        user?.isEnabled = true
        userRepository.save(user!!)
    }

    fun createRoleIfNotFound(name: String, privileges: Privilege): Role {
        val r = roleRepository.findByName(name)
        return if (r.isPresent) {
            r.get()
        } else {
            val role = Role(name = name)
            role.privileges = privileges
            roleRepository.save(role)
        }
    }

    fun createPrivilegeIfNotFound(name: String): Privilege {
        val p = privilegeRepository.findByName(name)
        return if (p.isPresent) {
            p.get()
        } else {
            val privilege = Privilege(name = name)
            privilegeRepository.save(privilege)
        }
    }

    fun isExpired(expiredTime: Instant?): Boolean {
        val currentTime = Instant.now()
        return currentTime.compareTo(expiredTime) > 0

    }


}