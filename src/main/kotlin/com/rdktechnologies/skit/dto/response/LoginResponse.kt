package com.rdktechnologies.skit.dto.response


data class LoginResponse(
        var error: Boolean? = null,
        var statusCode: Int? = null,
        var message: String? = null,
        var token: String? = null,
        var data: LoginUserData? = null
)

data class LoginUserData(
        var id: Long? = null,
        var firstName: String? = null,
        var lastName: String? = null,
        var fullName: String? = null,
        var email:String?=null
)