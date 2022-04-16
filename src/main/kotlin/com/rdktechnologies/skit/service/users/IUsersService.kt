package com.rdktechnologies.skit.service.users

import com.rdktechnologies.skit.model.dto.app.*
import org.springframework.http.ResponseEntity

interface IUsersService {
 fun getAllUsers():ResponseEntity<Any>
 fun blockUsers(list:MutableList<Long>):ResponseEntity<Any>
 fun unblockUsers(list:MutableList<Long>):ResponseEntity<Any>
 fun deleteUsers(list:MutableList<Long>):ResponseEntity<Any>
}