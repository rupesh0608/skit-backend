package com.rdktechnologies.skit.entity

import javax.persistence.*


@Entity
data class Role(
        @Id
        @GeneratedValue(strategy = GenerationType.AUTO)
        var id: Long? = null,
        var name: String? = null,
        @OneToOne
        var privileges: Privilege ?= null
)
