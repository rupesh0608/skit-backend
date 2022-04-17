package com.rdktechnologies.skit.entity

import javax.persistence.*
@Entity
data class Jobs(
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    var id: Long? = null,
    var postName:String?=null,
    var boardName:String?=null,
    var qualifications:String?=null,
    var link:String?=null,
    var postDate:String?=null,
    var lastDate:String?=null,
    var category:String?=null,
    var status:String?="draft"
)
