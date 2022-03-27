package com.rdktechnologies.skit.dto

import javax.validation.constraints.Email
import javax.validation.constraints.NotEmpty
import javax.validation.constraints.NotNull
import javax.validation.constraints.Pattern
import javax.validation.constraints.Size

data class ChangePwdDto1(

        val otp: Long,
        @field:Email(message = "is invalid, please check.")
        @field:Pattern(regexp = ".+@.+\\..+", message = "is invalid, please check")
        var email: String,

        @field:NotEmpty(message = "must not be null or empty.")
        @field:Size(min = 8, max = 20, message = "must contain 8 characters length")
        // @field:Pattern(regexp = "(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#\$%^&-+=()])(?=\\\\S+\$).{8,20}",message="must contain 8 characters length and contain Upper Case, Special Character, numerals, Lower Case")
        var newPassword: String,

        @field:NotEmpty(message = "must not be null or empty.")
        @field:Size(min = 8, max = 20, message = "must contain 8 characters length")
        // @field:Pattern(regexp = "(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#\$%^&-+=()])(?=\\\\S+\$).{8,20}",message="must contain 8 characters length and contain Upper Case, Special Character, numerals, Lower Case")
        var confirmPassword: String

)
data class ChangePwdDto2(
        @field:NotNull(message = "must not be null or Empty")
        val userId: Long,
        @field:NotEmpty(message = "must not be null or empty.")
        @field:Size(min = 8, max = 20, message = "must contain 8 characters length")
        // @field:Pattern(regexp = "(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#\$%^&-+=()])(?=\\\\S+\$).{8,20}",message="must contain 8 characters length and contain Upper Case, Special Character, numerals, Lower Case")
        var oldPassword: String,
        @field:NotEmpty(message = "must not be null or empty.")
        @field:Size(min = 8, max = 20, message = "must contain 8 characters length")
        // @field:Pattern(regexp = "(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#\$%^&-+=()])(?=\\\\S+\$).{8,20}",message="must contain 8 characters length and contain Upper Case, Special Character, numerals, Lower Case")
        var newPassword: String,
        @field:NotEmpty(message = "must not be null or empty.")
        @field:Size(min = 8, max = 20, message = "must contain 8 characters length")
        // @field:Pattern(regexp = "(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#\$%^&-+=()])(?=\\\\S+\$).{8,20}",message="must contain 8 characters length and contain Upper Case, Special Character, numerals, Lower Case")
        var confirmPassword: String

)