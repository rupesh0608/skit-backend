package com.rdktechnologies.skit.dto

import javax.validation.constraints.*

data class UserDto(

        @field:NotEmpty(message = "must not be null or Empty")
        var firstName: String,

        @field:NotEmpty(message = "must not be null or empty.")
        var lastName: String,

        @field:Email(message="is invalid, please check.")
        @field:Pattern(regexp=".+@.+\\..+", message="is invalid, please check")
        var email: String,

        @field:NotEmpty(message="must not be null or empty.")
        @field:Size(min=8, max=20, message = "must contain 8 characters length")
       // @field:Pattern(regexp = "(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#\$%^&-+=()])(?=\\\\S+\$).{8,20}",message="must contain 8 characters length and contain Upper Case, Special Character, numerals, Lower Case")
        var password: String,

        @field:NotEmpty(message="must not be null or empty.")
        @field:Size(min=8, max=20, message = "must contain 8 characters length")
       // @field:Pattern(regexp = "(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#\$%^&-+=()])(?=\\\\S+\$).{8,20}",message="must contain 8 characters length and contain Upper Case, Special Character, numerals, Lower Case")
        var confirmPassword: String,

)
