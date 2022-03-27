package com.rdktechnologies.skit.repository

import com.rdktechnologies.skit.entity.ConfirmationOTP
import com.rdktechnologies.skit.entity.User
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository
import java.util.Optional

@Repository
interface OTPRepository : JpaRepository<ConfirmationOTP,Long> {
   fun findByUser(user: User):Optional<ConfirmationOTP>
}