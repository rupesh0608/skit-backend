package com.rdktechnologies.skit.model.response.adminpannel

import com.rdktechnologies.skit.entity.Jobs

data class AllJobsResponse (
    var error:Boolean?=false,
    var message:String?="",
    var data:MutableList<Jobs>?= mutableListOf()
)