package com.rdktechnologies.skit.service.users


import com.ongraph.daverick.recipie.social.app.constants.Roles
import com.rdktechnologies.skit.entity.User
import com.rdktechnologies.skit.model.response.app.*
import com.rdktechnologies.skit.repository.*
import com.rdktechnologies.skit.utils.JWTUtility
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.stereotype.Service


@Service
class UsersService : IUsersService {
    @Autowired
    lateinit var jwtUtility: JWTUtility

    @Autowired
    lateinit var authenticationManager: AuthenticationManager

    @Autowired
    private lateinit var userRepository: UserRepository


    @Autowired
    private lateinit var roleRepository: RoleRepository

    @Autowired
    private lateinit var privilegeRepository: PrivilegeRepository
    override fun getAllUsers(): ResponseEntity<Any> {
        val data=userRepository.findAll()
        val verifiedList= mutableListOf<User>()
        val blockedList= mutableListOf<User>()
        for (item in data){
            if(item.roles?.name==Roles.ROLE_USER){
                if(item.isAccountNonExpired==false || item .isEnabled==false){
                     blockedList.add(item)
                }else{
                    verifiedList.add(item)
                }

            }
        }
        return ResponseEntity.ok(AllUsersResponse(false,"",verifiedList,blockedList))
    }

    override fun blockUsers(list: MutableList<Long>): ResponseEntity<Any> {
           for (id in list){
              val data=userRepository.findById(id)
               if(data.isPresent){
                   val user=data.get()
                   user.isAccountNonExpired=false
                   user.isEnabled=false
                   user.isCredentialsNonExpired=false
                   userRepository.save(user)
               }
           }

        return ResponseEntity.ok(SimpleResponse(false,200,"Selected Users Blocked Successfully...."))
    }

    override fun unblockUsers(list: MutableList<Long>): ResponseEntity<Any> {
        for (id in list){
            val data=userRepository.findById(id)
            if(data.isPresent){
                val user=data.get()
                user.isAccountNonExpired=true
                user.isEnabled=true
                user.isCredentialsNonExpired=true
                userRepository.save(user)
            }
        }
        return ResponseEntity.ok(SimpleResponse(false,200,"Selected Users Unblocked Successfully...."))
    }

    override fun deleteUsers(list: MutableList<Long>): ResponseEntity<Any> {
        for (id in list){
            val data=userRepository.findById(id)
            if(data.isPresent){
                val user=data.get()
                userRepository.delete(user)
            }
        }

        return ResponseEntity.ok(SimpleResponse(false,200,"Selected Users Account Deleted Successfully...."))
    }


}