package com.rdktechnologies.skit.service.auth

import com.rdktechnologies.skit.entity.Role
import com.rdktechnologies.skit.entity.User
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Component

@Component
class AuthUserDetails : UserDetails {

    lateinit var users: User

    fun addEntity(users: User) {
        this.users = users
    }

    fun getUserData(): User {
        return users
    }

    override fun getAuthorities(): MutableCollection<out GrantedAuthority> {
        return getGrantedAuthorities(getPrivileges(users.roles))
    }
    private fun getPrivileges(roles: Role?): MutableList<String?> {
        val privileges: MutableList<String?> = ArrayList()
        privileges.add(roles?.privileges?.name)
        return privileges
    }
    private fun getGrantedAuthorities(privileges: MutableList<String?>): MutableList<GrantedAuthority> {
        val authorities: MutableList<GrantedAuthority> = ArrayList()
        for (privilege in privileges) {
            authorities.add(SimpleGrantedAuthority(privilege))
        }
        return authorities
    }

    override fun getPassword(): String {
        return users.password!!
    }

    override fun getUsername(): String {
        return users.email!!
    }

    override fun isAccountNonExpired(): Boolean {
        return users.isAccountNonExpired!!
    }

    override fun isAccountNonLocked(): Boolean {
        return users.isAccountNonLocked!!
    }

    override fun isCredentialsNonExpired(): Boolean {
        return users.isCredentialsNonExpired!!
    }

    override fun isEnabled(): Boolean {
        return users.isEnabled!!
    }
}