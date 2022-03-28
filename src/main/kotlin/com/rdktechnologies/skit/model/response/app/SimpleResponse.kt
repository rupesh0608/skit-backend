package com.rdktechnologies.skit.model.response.app

data class SimpleResponse (
    var error:Boolean?=null,
    var statusCode:Int?=null,
    var message:String?=null
)