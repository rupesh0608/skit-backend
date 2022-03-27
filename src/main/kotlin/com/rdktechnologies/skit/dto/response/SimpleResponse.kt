package com.rdktechnologies.skit.dto.response

data class SimpleResponse (
    var error:Boolean?=null,
    var statusCode:Int?=null,
    var message:String?=null
)