package com.rdktechnologies.skit.repository

import com.rdktechnologies.skit.entity.ConfirmationToken
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository
import java.util.Optional

@Repository
interface TokenRepository : JpaRepository<ConfirmationToken,Long> {
   fun findByToken(token:String):Optional<ConfirmationToken>
}