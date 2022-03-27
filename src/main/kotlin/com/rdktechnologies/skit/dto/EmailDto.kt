package com.rdktechnologies.skit.dto

import javax.validation.constraints.Email
import javax.validation.constraints.Pattern

data class EmailDto (
        @field:Email(message="is invalid, please check.")
        @field:Pattern(regexp=".+@.+\\..+", message="is invalid, please check")
        var email: String,
        )