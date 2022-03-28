package com.rdktechnologies.skit.model.dto.app

import javax.validation.constraints.Email
import javax.validation.constraints.NotEmpty
import javax.validation.constraints.Pattern

data class SocialLoginDto(
        @field:NotEmpty(message = "must not be null or Empty")
        var firstName: String,

        @field:NotEmpty(message = "must not be null or empty.")
        var lastName: String,

        @field:NotEmpty(message = "must not be null or empty.")
        var  pic_url: String,

        @field:Email(message = "is invalid, please check.")
        @field:Pattern(regexp = ".+@.+\\..+", message = "is invalid, please check")
        var email: String
)
