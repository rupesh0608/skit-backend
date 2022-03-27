package com.rdktechnologies.skit.entity


import java.time.Instant
import javax.persistence.*
import javax.validation.Valid

@Entity
@Table(name = "forgot_otp")
data class ConfirmationOTP(
        @Id
        @GeneratedValue(strategy = GenerationType.AUTO)
        var id: Long? = null,
        @Valid
        @OneToOne(cascade = [CascadeType.ALL])
        var user: User? = null,
        var otp: Long? = null,
        var createdAt: Instant? = null,
        var expiredAt: Instant? = null,
)