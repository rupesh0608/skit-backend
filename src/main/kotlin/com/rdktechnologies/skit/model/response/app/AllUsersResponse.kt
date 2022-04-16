package com.rdktechnologies.skit.model.response.app

import com.rdktechnologies.skit.entity.User

data class AllUsersResponse(
    var error:Boolean?=false,
    var message:String?=null,
    var verifiedUsers: MutableList<User> = arrayListOf(),
    var BLockedUsers: MutableList<User> = arrayListOf()
)
