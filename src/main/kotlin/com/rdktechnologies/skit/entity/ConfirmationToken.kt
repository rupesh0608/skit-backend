package com.rdktechnologies.skit.entity


import java.time.Instant
import javax.persistence.*
import javax.validation.Valid

@Entity
@Table(name = "token")
data class ConfirmationToken(
        @Id
        @GeneratedValue(strategy = GenerationType.AUTO)
        var id: Long? = null,
        @Valid
        @OneToOne(cascade = [CascadeType.ALL])
        var users: User? = null,
        var token: String? = null,
        var createdAt: Instant? = null,
        var expiredAt: Instant? = null,
)