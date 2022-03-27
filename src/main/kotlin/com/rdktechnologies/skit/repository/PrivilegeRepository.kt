package com.rdktechnologies.skit.repository

import com.rdktechnologies.skit.entity.Privilege
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository
import java.util.*

@Repository
interface PrivilegeRepository : JpaRepository<Privilege,Long> {
    fun findByName(name:String): Optional<Privilege>
}