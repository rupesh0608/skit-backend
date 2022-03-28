package com.rdktechnologies.skit.model.dto.app

import javax.validation.constraints.Email
import javax.validation.constraints.Pattern

data class ForgotPasswordDto(
        @field:Email(message="is invalid, please check.")
        @field:Pattern(regexp=".+@.+\\..+", message="is invalid, please check")
        var email: String,
)
