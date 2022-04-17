package com.rdktechnologies.skit.repository

import com.rdktechnologies.skit.entity.Jobs
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository

@Repository
interface JobsRepository : JpaRepository<Jobs,Long> {
}