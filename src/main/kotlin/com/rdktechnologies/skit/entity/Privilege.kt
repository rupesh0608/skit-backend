package com.rdktechnologies.skit.entity

import javax.persistence.*


@Entity
data class Privilege(
        @Id
        @GeneratedValue(strategy = GenerationType.AUTO)
        var id: Long? = null,
        var name: String? = null,
)
