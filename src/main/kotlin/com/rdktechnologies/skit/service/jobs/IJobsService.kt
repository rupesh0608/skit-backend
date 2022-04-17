package com.rdktechnologies.skit.service.jobs

import com.rdktechnologies.skit.model.dto.app.*
import com.rdktechnologies.skit.model.dto.app.adminpannel.JobDto
import com.rdktechnologies.skit.model.dto.app.adminpannel.UpdateJobDto
import org.springframework.http.ResponseEntity

interface IJobsService {
 fun saveJob(jobsDto:JobDto):ResponseEntity<Any>
 fun updateJob(updateJobDto: UpdateJobDto):ResponseEntity<Any>
 fun publishJob(id:Long):ResponseEntity<Any>
 fun unPublishJob(id:Long):ResponseEntity<Any>
 fun getAllJob():ResponseEntity<Any>
}