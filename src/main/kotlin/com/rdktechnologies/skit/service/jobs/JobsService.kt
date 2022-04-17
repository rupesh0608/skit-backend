package com.rdktechnologies.skit.service.jobs


import com.ongraph.daverick.recipie.social.app.constants.Roles
import com.rdktechnologies.skit.entity.Jobs
import com.rdktechnologies.skit.entity.User
import com.rdktechnologies.skit.error.exceptions.JobNotFoundException
import com.rdktechnologies.skit.model.dto.app.adminpannel.JobDto
import com.rdktechnologies.skit.model.dto.app.adminpannel.UpdateJobDto
import com.rdktechnologies.skit.model.response.adminpannel.AllJobsResponse
import com.rdktechnologies.skit.model.response.app.*
import com.rdktechnologies.skit.repository.*
import com.rdktechnologies.skit.utils.JWTUtility
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.stereotype.Service


@Service
class JobsService : IJobsService {

    @Autowired
    private lateinit var jobsRepository: JobsRepository

    override fun saveJob(jobsDto: JobDto): ResponseEntity<Any> {
        jobsRepository.save(Jobs(
            postName = jobsDto.postName,
            boardName = jobsDto.boardName,
            qualifications = jobsDto.qualifications,
            category=jobsDto.category,
            link = jobsDto.link,
            postDate = jobsDto.postDate,
            lastDate = jobsDto.lastDate,
            status = jobsDto.status
        ))
        return ResponseEntity.ok(SimpleResponse(false,200,"Job Submitted Successfully..."))
    }
    override fun updateJob(updateJobDto: UpdateJobDto): ResponseEntity<Any> {

        val data=jobsRepository.findById(updateJobDto.id!!)
        if(data.isPresent){
            val job=data.get()
                job.postName= updateJobDto.postName
                job.boardName = updateJobDto.boardName
                job.qualifications = updateJobDto.qualifications
                job.category=updateJobDto.category
                job.link =updateJobDto.link
                job.postDate = updateJobDto.postDate
                job.lastDate = updateJobDto.lastDate
                job.status =updateJobDto.status
            jobsRepository.save(job)
            return ResponseEntity.ok(SimpleResponse(false,200,"Job Updated Successfully..."))
        }else{
            throw JobNotFoundException("job not found with requested job_id")
        }


    }

    override fun publishJob(id:Long): ResponseEntity<Any> {
        val data=jobsRepository.findById(id)
        if(data.isPresent){
            val job=data.get()
            job.status="published"
            jobsRepository.save(job)
            return ResponseEntity.ok(SimpleResponse(false,200,"Job Published Successfully..."))
        }else{
            throw JobNotFoundException("job not found with requested job_id...")
        }


    }
    override fun unPublishJob(id:Long): ResponseEntity<Any> {
        val data=jobsRepository.findById(id)
        if(data.isPresent){
            val job=data.get()
            job.status="draft"
            jobsRepository.save(job)
            return ResponseEntity.ok(SimpleResponse(false,200,"Job UnPublished Successfully..."))
        }else{
            throw JobNotFoundException("job not found with requested job_id...")
        }


    }

    override fun getAllJob(): ResponseEntity<Any> {
        return ResponseEntity.ok(AllJobsResponse(false,"",jobsRepository.findAll()))
    }


}