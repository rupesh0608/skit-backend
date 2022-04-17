package com.rdktechnologies.skit.controller


import com.rdktechnologies.skit.model.dto.app.*
import com.rdktechnologies.skit.model.dto.app.adminpannel.JobDto
import com.rdktechnologies.skit.model.dto.app.adminpannel.UpdateJobDto
import com.rdktechnologies.skit.model.dto.app.adminpannel.publish_unpublish_JobDto
import com.rdktechnologies.skit.service.auth.IAuthService
import com.rdktechnologies.skit.service.jobs.JobsService
import com.rdktechnologies.skit.service.users.UsersService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import javax.validation.Valid



@CrossOrigin(origins = ["http://localhost:4200"])
@RestController
@RequestMapping("/api/admin/jobs/")
class AdminJobsController {

    @Autowired
    private lateinit var authService : IAuthService
    @Autowired
    private lateinit var jobsService: JobsService

    @PostMapping("/save")
    fun saveJobs(@RequestBody(required = true)jobDto: JobDto):ResponseEntity<Any>{
        return jobsService.saveJob(jobDto)
    }
    @PostMapping("/update")
    fun saveJobs(@RequestBody(required = true)updateJobDto: UpdateJobDto):ResponseEntity<Any>{
        return jobsService.updateJob(updateJobDto)
    }
    @PostMapping("/publish")
    fun publishJob(@RequestBody(required = true) publishUnpublishJobdto: publish_unpublish_JobDto):ResponseEntity<Any>{
        return jobsService.publishJob(publishUnpublishJobdto.id)
    }
    @PostMapping("/unpublish")
    fun unPublishJob(@RequestBody(required = true) publishUnpublishJobdto: publish_unpublish_JobDto):ResponseEntity<Any>{
        return jobsService.unPublishJob(publishUnpublishJobdto.id)
    }
    @GetMapping("/all")
    fun getAllJobs():ResponseEntity<Any>{
        return jobsService.getAllJob()
    }

}